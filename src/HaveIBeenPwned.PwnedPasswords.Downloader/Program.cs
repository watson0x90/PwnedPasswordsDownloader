using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Channels;

using HaveIBeenPwned.PwnedPasswords;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

using Polly;
using Polly.Retry;

using Spectre.Console;
using Spectre.Console.Cli;

IHostBuilder host = CreateHostBuilder(args);
host.ConfigureLogging(builder =>
{
    builder.ClearProviders();
});

var registrar = new TypeRegistrar(host);

var app = new CommandApp<PwnedPasswordsDownloader>(registrar);

app.Configure(config => config.PropagateExceptions());

try
{
    return await app.RunAsync(args);
}
catch (Exception ex)
{
    AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
    return -99;
}

static IHostBuilder CreateHostBuilder(string[] args) =>
    Host
    .CreateDefaultBuilder(args)
    .ConfigureServices((hostContext, services) =>
    {
        services
        .AddHttpClient("PwnedPasswords")
        .UseSocketsHttpHandler((handler, provider) =>
        {
            handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            handler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13 | System.Security.Authentication.SslProtocols.Tls12;
            handler.EnableMultipleHttp2Connections = true;
        })
        .ConfigureHttpClient(client =>
        {
            client.BaseAddress = new Uri("https://api.pwnedpasswords.com/range/");
            string? process = Environment.ProcessPath;
            if (process != null)
            {
                client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("hibp-downloader", FileVersionInfo.GetVersionInfo(process).ProductVersion));
            }

            client.DefaultRequestVersion = HttpVersion.Version20;
            client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
            client.Timeout = TimeSpan.FromSeconds(30); // 30 second timeout per request
        });
    });

internal sealed class RetryItem
{
    public int HashIndex { get; set; }
    public bool FetchNtlm { get; set; }
    public int AttemptCount { get; set; }
    public string? LastError { get; set; }
}

internal sealed class FailedDownload
{
    public int HashIndex { get; set; }
    public bool FetchNtlm { get; set; }
    public int AttemptCount { get; set; }
    public string LastError { get; set; } = string.Empty;
    public DateTime LastAttempt { get; set; }
}

internal sealed class Statistics
{
    public int HashesDownloaded;
    public int CloudflareRequests;
    public int CloudflareHits;
    public int CloudflareMisses;
    public long CloudflareRequestTimeTotal;
    public long ElapsedMilliseconds;
    public int FailedDownloads;
    public int AbandonedDownloads;
    public double HashesPerSecond => HashesDownloaded / (ElapsedMilliseconds / 1000.0);
}

internal sealed class PwnedPasswordsDownloader : AsyncCommand<PwnedPasswordsDownloader.Settings>
{
    private static readonly ResiliencePropertyKey<string> s_resiliencePropertyKey = new("uri");
    private readonly Statistics _statistics = new();
    private readonly HttpClient _httpClient;
    private readonly ResiliencePipeline<HttpResponseMessage> _pipeline;
    private readonly ConcurrentQueue<RetryItem> _retryQueue = new();
    private readonly ConcurrentBag<FailedDownload> _persistentFailures = new();
    private readonly HashSet<int> _completedRanges = new();
    private readonly SemaphoreSlim _retryQueueSignal = new(0);
    private int _activeDownloads = 0;
    private const int MaxRetryAttempts = 5;

    public PwnedPasswordsDownloader(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient("PwnedPasswords");
        _pipeline = new ResiliencePipelineBuilder<HttpResponseMessage>().AddRetry(new RetryStrategyOptions<HttpResponseMessage>
        {
            ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                .HandleResult(response => !response.IsSuccessStatusCode)
                .Handle<HttpRequestException>()
                .Handle<OperationCanceledException>()
                .Handle<TimeoutException>()
                .Handle<TaskCanceledException>(),
            MaxRetryAttempts = 5, // Let Polly handle most transient failures
            BackoffType = DelayBackoffType.Exponential,
            UseJitter = true, // Add jitter to prevent thundering herd
            Delay = TimeSpan.FromSeconds(1),
            MaxDelay = TimeSpan.FromSeconds(30),
            OnRetry = OnRequestErrorAsync
        }).Build();
    }

    static ValueTask OnRequestErrorAsync(OnRetryArguments<HttpResponseMessage> args)
    {
        string uri = args.Context.Properties.GetValue(s_resiliencePropertyKey, "");
        AnsiConsole.MarkupLine(args.Outcome.Exception != null
            ? $"[yellow]Failed attempt #{args.AttemptNumber} while fetching {uri}. Exception is {args.Outcome.Exception.GetType().Name} and message: {args.Outcome.Exception.Message}.[/]"
            : $"[yellow]Failed attempt #{args.AttemptNumber} while fetching {uri}. Response contained HTTP Status code {args.Outcome.Result?.StatusCode}.[/]");

        return ValueTask.CompletedTask;
    }

    public sealed class Settings : CommandSettings
    {
        [Description("Name of the output. Defaults to pwnedpasswords, which writes the output to pwnedpasswords.txt for single file output, or a directory called pwnedpasswords.")]
        [CommandArgument(0, "[outputFile]")]
        public string OutputFile { get; init; } = "pwnedpasswords";

        [Description("The number of parallel requests to make to Have I Been Pwned to download the hash ranges. If omitted or less than 2, defaults to eight times the number of processors on the machine.")]
        [CommandOption("-p||--parallelism")]
        [DefaultValue(0)]
        public int Parallelism { get; set; }

        [Description("When set, overwrite any existing files while writing the results. Defaults to false.")]
        [CommandOption("-o|--overwrite")]
        [DefaultValue(false)]
        public bool Overwrite { get; set; } = false;

        [Description("When set, writes the hash ranges into a single .txt file. Otherwise downloads ranges to individual files into a subfolder. If ommited defaults to single file.")]
        [CommandOption("-s|--single")]
        [DefaultValue(true)]
        public bool SingleFile { get; set; } = true;

        [Description("When set, fetches NTLM hashes instead of SHA1.")]
        [CommandOption("-n|--ntlm")]
        [DefaultValue(false)]
        public bool FetchNtlm { get; set; } = false;

        [Description("When set, resume from a previous interrupted download using checkpoint file.")]
        [CommandOption("-r|--resume")]
        [DefaultValue(false)]
        public bool Resume { get; set; } = false;

        [Description("Maximum number of retry attempts for failed downloads. Defaults to 5.")]
        [CommandOption("--max-retries")]
        [DefaultValue(5)]
        public int MaxRetries { get; set; } = 5;

        [Description("Timeout in seconds for each HTTP request. Defaults to 30.")]
        [CommandOption("--timeout")]
        [DefaultValue(30)]
        public int TimeoutSeconds { get; set; } = 30;
    }

    public override async Task<int> ExecuteAsync([NotNull] CommandContext context, [NotNull] Settings settings)
    {
        if (settings.Parallelism < 2)
        {
            settings.Parallelism = Math.Max(Environment.ProcessorCount * 8, 2);
        }

        try
        {
            // Load checkpoint if resuming
            if (settings.Resume)
            {
                await LoadCheckpoint(settings.OutputFile);
            }

            await AnsiConsole.Progress()
                .AutoRefresh(false) // Turn off auto refresh
                .AutoClear(false)   // Do not remove the task list when done
                .HideCompleted(false)   // Hide tasks as they are completed
                .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new RemainingTimeColumn(), new SpinnerColumn())
                .StartAsync(async ctx =>
                {
                    if (settings.SingleFile)
                    {
                        if (File.Exists($"{settings.OutputFile}.txt"))
                        {
                            if (!settings.Overwrite)
                            {
                                AnsiConsole.MarkupLine($"Output file {settings.OutputFile.EscapeMarkup()}.txt already exists. Use -o if you want to overwrite it.");
                                return;
                            }

                            File.Delete($"{settings.OutputFile}.txt");
                        }
                    }
                    else
                    {
                        if (!Directory.Exists(settings.OutputFile))
                        {
                            Directory.CreateDirectory(settings.OutputFile);
                        }

                        if (!settings.Overwrite && Directory.EnumerateFiles(settings.OutputFile).Any())
                        {
                            AnsiConsole.MarkupLine($"Output directory {settings.OutputFile.EscapeMarkup()} already exists and is not empty. Use -o if you want to overwrite files.");
                            return;
                        }
                    }


                    var timer = Stopwatch.StartNew();
                    ProgressTask progressTask = ctx.AddTask("[green]Hash ranges downloaded[/]", true, 1024 * 1024);
                    Task processTask = ProcessRanges(settings);

                    do
                    {
                        progressTask.Value = _statistics.HashesDownloaded;
                        ctx.Refresh();
                        await Task.Delay(100).ConfigureAwait(false);
                    }
                    while (!processTask.IsCompleted);

                    if (processTask.Exception is not null)
                    {
                        throw processTask.Exception;
                    }

                    _statistics.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                    progressTask.Value = _statistics.HashesDownloaded;
                    ctx.Refresh();
                    progressTask.StopTask();
                });

            AnsiConsole.MarkupLine($"Finished downloading all hash ranges in {_statistics.ElapsedMilliseconds:N0}ms ({_statistics.HashesPerSecond:N2} hashes per second).");
            AnsiConsole.MarkupLine($"We made {_statistics.CloudflareRequests:N0} Cloudflare requests (avg response time: {(double)_statistics.CloudflareRequestTimeTotal / _statistics.CloudflareRequests:N2}ms). Of those, Cloudflare had already cached {_statistics.CloudflareHits:N0} requests, and made {_statistics.CloudflareMisses:N0} requests to the Have I Been Pwned origin server.");
            
            if (_statistics.FailedDownloads > 0 || _statistics.AbandonedDownloads > 0)
            {
                AnsiConsole.MarkupLine($"[yellow]Download issues: {_statistics.FailedDownloads:N0} failed downloads were retried, {_statistics.AbandonedDownloads:N0} downloads were abandoned after {settings.MaxRetries} attempts.[/]");
            }

            // Save checkpoint and failed downloads
            await SaveCheckpoint(settings.OutputFile);
            await SaveFailedDownloads(settings.OutputFile);

            // Clean up checkpoint file if download completed successfully
            if (_statistics.AbandonedDownloads == 0 && _completedRanges.Count >= 1024 * 1024)
            {
                try
                {
                    File.Delete(GetCheckpointFilePath(settings.OutputFile));
                    AnsiConsole.MarkupLine("[green]Download completed successfully. Checkpoint file removed.[/]");
                }
                catch { /* Ignore cleanup errors */ }
            }

            return 0;
        }
        catch (Exception e)
        {
            AnsiConsole.MarkupLine($"Failed to download hash ranges: {e.Message}");
            AnsiConsole.WriteException(e);

            // Save checkpoint and failed downloads even on error
            await SaveCheckpoint(settings.OutputFile);
            await SaveFailedDownloads(settings.OutputFile);

            return -1;
        }
    }

    private string GetCheckpointFilePath(string outputFile) => $"{outputFile}.checkpoint.json";
    private string GetFailedDownloadsFilePath(string outputFile) => $"{outputFile}.failed.json";

    private async Task LoadCheckpoint(string outputFile)
    {
        string checkpointFile = GetCheckpointFilePath(outputFile);
        if (File.Exists(checkpointFile))
        {
            try
            {
                var json = await File.ReadAllTextAsync(checkpointFile);
                var completed = JsonSerializer.Deserialize<HashSet<int>>(json);
                if (completed != null)
                {
                    foreach (var item in completed)
                    {
                        _completedRanges.Add(item);
                    }
                    AnsiConsole.MarkupLine($"[green]Loaded checkpoint: {_completedRanges.Count:N0} ranges already downloaded.[/]");
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[yellow]Warning: Could not load checkpoint file: {ex.Message}[/]");
            }
        }
    }

    private async Task SaveCheckpoint(string outputFile)
    {
        try
        {
            var json = JsonSerializer.Serialize(_completedRanges, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(GetCheckpointFilePath(outputFile), json);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[yellow]Warning: Could not save checkpoint: {ex.Message}[/]");
        }
    }

    private async Task SaveFailedDownloads(string outputFile)
    {
        if (_persistentFailures.IsEmpty)
            return;

        try
        {
            var json = JsonSerializer.Serialize(_persistentFailures.ToList(), new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(GetFailedDownloadsFilePath(outputFile), json);
            AnsiConsole.MarkupLine($"[yellow]Saved {_persistentFailures.Count} failed downloads to {GetFailedDownloadsFilePath(outputFile)}[/]");
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Warning: Could not save failed downloads: {ex.Message}[/]");
        }
    }

    private void MarkRangeCompleted(int hashIndex)
    {
        lock (_completedRanges)
        {
            _completedRanges.Add(hashIndex);
        }
    }

    private bool IsRangeCompleted(int hashIndex)
    {
        lock (_completedRanges)
        {
            return _completedRanges.Contains(hashIndex);
        }
    }

    private async Task<Stream?> GetPwnedPasswordsRangeFromWeb(int i, bool fetchNtlm, int attemptCount = 1, int maxAttempts = MaxRetryAttempts)
    {
        // Skip if already completed (for resume functionality)
        if (IsRangeCompleted(i))
        {
            return null;
        }

        Interlocked.Increment(ref _activeDownloads);
        try
        {
            var cloudflareTimer = Stopwatch.StartNew();
            string requestUri = GetHashRange(i);
            if (fetchNtlm)
            {
                requestUri += "?mode=ntlm";
            }

            ResilienceContext context = ResilienceContextPool.Shared.Get();
            context.Properties.Set(s_resiliencePropertyKey, $"{_httpClient.BaseAddress}{requestUri}");
            HttpResponseMessage response = await _pipeline.ExecuteAsync(async (ResilienceContext resilienceContext) => await _httpClient.GetAsync(requestUri, resilienceContext.CancellationToken).ConfigureAwait(false), context);
            ResilienceContextPool.Shared.Return(context);
            Stream content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            Interlocked.Add(ref _statistics.CloudflareRequestTimeTotal, cloudflareTimer.ElapsedMilliseconds);
            Interlocked.Increment(ref _statistics.CloudflareRequests);
            if (!response.Headers.TryGetValues("CF-Cache-Status", out IEnumerable<string>? values))
            {
                return content;
            }

            switch (values.FirstOrDefault())
            {
                case "HIT":
                    Interlocked.Increment(ref _statistics.CloudflareHits);
                    break;
                default:
                    Interlocked.Increment(ref _statistics.CloudflareMisses);
                    break;
            }

            return content;
        }
        catch (Exception ex) when (ex is TaskCanceledException or TimeoutException or HttpRequestException)
        {
            string errorMsg = ex.GetType().Name + ": " + ex.Message;
            
            if (attemptCount < maxAttempts)
            {
                // Add to retry queue for later processing
                _retryQueue.Enqueue(new RetryItem { HashIndex = i, FetchNtlm = fetchNtlm, AttemptCount = attemptCount + 1, LastError = errorMsg });
                _retryQueueSignal.Release(); // Signal that a retry is available
                Interlocked.Increment(ref _statistics.FailedDownloads);
                return null;
            }
            else
            {
                // Persistent failure - save for later analysis
                _persistentFailures.Add(new FailedDownload 
                { 
                    HashIndex = i, 
                    FetchNtlm = fetchNtlm, 
                    AttemptCount = attemptCount,
                    LastError = errorMsg,
                    LastAttempt = DateTime.UtcNow
                });
                Interlocked.Increment(ref _statistics.AbandonedDownloads);
                AnsiConsole.MarkupLine($"[red]Abandoned range {GetHashRange(i)} after {maxAttempts} attempts: {errorMsg}[/]");
                return null;
            }
        }
        finally
        {
            Interlocked.Decrement(ref _activeDownloads);
        }
    }

    private async Task<Stream?> ProcessRetryItem(RetryItem retryItem, int maxAttempts = MaxRetryAttempts)
    {
        // Progressive delay with jitter before retrying to avoid overwhelming the server
        int baseDelay = retryItem.AttemptCount * 2;
        int jitter = Random.Shared.Next(0, 1000); // 0-1 second jitter
        await Task.Delay(TimeSpan.FromSeconds(baseDelay) + TimeSpan.FromMilliseconds(jitter));
        return await GetPwnedPasswordsRangeFromWeb(retryItem.HashIndex, retryItem.FetchNtlm, retryItem.AttemptCount, maxAttempts);
    }

    private static string GetHashRange(int i)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, i);
        return Convert.ToHexString(bytes)[3..];
    }

    private async Task ProcessRanges(Settings settings)
    {
        if (settings.SingleFile)
        {
            Channel<Task<(int hashIndex, Stream? stream)>> downloadTasks = Channel.CreateBounded<Task<(int hashIndex, Stream? stream)>>(new BoundedChannelOptions(settings.Parallelism) { SingleReader = true, SingleWriter = true, AllowSynchronousContinuations = true });
            await using FileStream file = File.Open($"{settings.OutputFile}.txt", new FileStreamOptions { Access = FileAccess.Write, BufferSize = 32767, Mode = FileMode.Create, Options = FileOptions.Asynchronous, Share = FileShare.None });
            await using StreamWriter writer = new(file);
            Task producerTask = StartDownloadsSingleFile(downloadTasks.Writer, settings.FetchNtlm, settings.MaxRetries);
            
            int checkpointCounter = 0;
            await foreach (Task<(int hashIndex, Stream? stream)> item in downloadTasks.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                var (hashIndex, inputStream) = await item.ConfigureAwait(false);
                if (inputStream != null)
                {
                    string prefix = GetHashRange(hashIndex);
                    await using (inputStream)
                    {
                        using StreamReader reader = new(inputStream);
                        while (await reader.ReadLineAsync() is { } line)
                        {
                            if (line.Length > 0)
                            {
                                await writer.WriteLineAsync($"{prefix}{line}");
                            }
                        }
                    }
                    await writer.FlushAsync();
                    MarkRangeCompleted(hashIndex);
                    Interlocked.Increment(ref _statistics.HashesDownloaded);
                    
                    // Periodically save checkpoint every 10000 ranges
                    if (++checkpointCounter % 10000 == 0)
                    {
                        await SaveCheckpoint(settings.OutputFile);
                    }
                }
                // If inputStream is null, it means the download failed and will be retried or abandoned
            }

            await producerTask.ConfigureAwait(false);
        }
        else
        {
            await Parallel.ForEachAsync(EnumerateRanges(), new ParallelOptions
            {
                MaxDegreeOfParallelism = settings.Parallelism,
                TaskScheduler = TaskScheduler.Default
            }, async (i, _) =>
            {
                await DownloadRangeToFile(i, settings.OutputFile, settings.FetchNtlm, settings.MaxRetries).ConfigureAwait(false);
            });

            // Process retry queue for file-based downloads with proper synchronization
            while (true)
            {
                if (_retryQueue.TryDequeue(out RetryItem? retryItem))
                {
                    await DownloadRetryRangeToFile(retryItem, settings.OutputFile, settings.MaxRetries).ConfigureAwait(false);
                    continue;
                }

                if (_activeDownloads == 0 && _retryQueue.IsEmpty)
                {
                    break;
                }

                await Task.Delay(100);
            }
        }
    }

    private static IEnumerable<int> EnumerateRanges()
    {
        for (int i = 0; i < 1024 * 1024; i++)
        {
            yield return i;
        }
    }

    private async Task StartDownloadsSingleFile(ChannelWriter<Task<(int hashIndex, Stream? stream)>> channelWriter, bool fetchNtlm, int maxRetries)
    {
        try
        {
            // Start initial downloads
            foreach (int i in EnumerateRanges())
            {
                int hashIndex = i; // Capture for closure
                await channelWriter.WriteAsync(Task.Run(async () =>
                {
                    var stream = await GetPwnedPasswordsRangeFromWeb(hashIndex, fetchNtlm, 1, maxRetries);
                    return (hashIndex, stream);
                }));
            }

            // Process retry queue - wait for all active downloads to complete and retry queue to be empty
            while (true)
            {
                // Try to dequeue immediately
                if (_retryQueue.TryDequeue(out RetryItem? retryItem))
                {
                    await channelWriter.WriteAsync(Task.Run(async () =>
                    {
                        var stream = await ProcessRetryItem(retryItem, maxRetries);
                        return (retryItem.HashIndex, stream);
                    }));
                    continue;
                }

                // If nothing in queue, check if there are still active downloads that might add more
                if (_activeDownloads == 0)
                {
                    // Double-check the queue after confirming no active downloads
                    if (_retryQueue.IsEmpty)
                    {
                        break;
                    }
                }
                else
                {
                    // Wait for signal that a retry was added, or timeout to check status
                    await _retryQueueSignal.WaitAsync(TimeSpan.FromMilliseconds(100));
                }
            }

            channelWriter.TryComplete();
        }
        catch (Exception e)
        {
            channelWriter.TryComplete(e);
        }
    }

    private async Task DownloadRangeToFile(int currentHash, string outputDirectory, bool fetchNtlm, int maxRetries)
    {
        Stream? stream = await GetPwnedPasswordsRangeFromWeb(currentHash, fetchNtlm, 1, maxRetries).ConfigureAwait(false);
        if (stream != null)
        {
            await using (stream)
            {
                using SafeFileHandle handle = File.OpenHandle(Path.Combine(outputDirectory, $"{GetHashRange(currentHash)}.txt"), FileMode.Create, FileAccess.Write,
                    FileShare.None, FileOptions.Asynchronous);
                await handle.CopyFrom(stream).ConfigureAwait(false);
            }
            MarkRangeCompleted(currentHash);
            Interlocked.Increment(ref _statistics.HashesDownloaded);
        }
    }

    private async Task DownloadRetryRangeToFile(RetryItem retryItem, string outputDirectory, int maxRetries)
    {
        Stream? stream = await ProcessRetryItem(retryItem, maxRetries).ConfigureAwait(false);
        if (stream != null)
        {
            await using (stream)
            {
                using SafeFileHandle handle = File.OpenHandle(Path.Combine(outputDirectory, $"{GetHashRange(retryItem.HashIndex)}.txt"), FileMode.Create, FileAccess.Write,
                    FileShare.None, FileOptions.Asynchronous);
                await handle.CopyFrom(stream).ConfigureAwait(false);
            }
            MarkRangeCompleted(retryItem.HashIndex);
            Interlocked.Increment(ref _statistics.HashesDownloaded);
        }
    }
}

public sealed class TypeRegistrar(IHostBuilder builder) : ITypeRegistrar
{
    public ITypeResolver Build() => new TypeResolver(builder.Build());

    public void Register(Type service, Type implementation) => builder.ConfigureServices((_, services) => services.AddSingleton(service, implementation));
    public void RegisterInstance(Type service, object implementation) => builder.ConfigureServices((_, services) => services.AddSingleton(service, implementation));
    public void RegisterLazy(Type service, Func<object> func)
    {
        ArgumentNullException.ThrowIfNull(func);
        builder.ConfigureServices((_, services) => services.AddSingleton(service, _ => func()));
    }
}

public sealed class TypeResolver(IHost provider) : ITypeResolver, IDisposable
{
    private readonly IHost _host = provider ?? throw new ArgumentNullException(nameof(provider));
    public object? Resolve(Type? type) => type != null ? _host.Services.GetService(type) : null;
    public void Dispose() => _host.Dispose();
}
