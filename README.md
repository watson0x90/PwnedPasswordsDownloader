# What is haveibeenpwned-downloader?
`haveibeenpwned-downloader` is a [dotnet tool](https://docs.microsoft.com/en-us/dotnet/core/tools/global-tools) to download all Pwned Passwords hash ranges and save them offline so they can be used without a dependency on the k-anonymity API.

An alternative to running this tool is to use Zsolt Müller's cURL approach in https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader/issues/79 that makes use of a glob pattern and parallelism.

# Installation

## Prerequisites
You'll need to install the latest [LTS (Long Term Support)](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) or [STS (Short Term Support)](https://dotnet.microsoft.com/en-us/download/dotnet/9.0) version of the .NET SDK to be able to install and run the tool.

## How to install
1. Open a command line window
2. Run `dotnet tool install --global haveibeenpwned-downloader`

## How to update to the latest version
1. Open a command line window
2. Run `dotnet tool update --global haveibeenpwned-downloader`

### Troubleshooting
If the installer is unable to resolve the package, then you can run the following and then try again.
```
dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org
```

# Usage Examples

## **Windows**


### Download all SHA1 hashes to a single txt file called `pwnedpasswords.txt`
`haveibeenpwned-downloader.exe pwnedpasswords`

### Download all SHA1 hashes to individual txt files into a custom directory called `hashes`
`haveibeenpwned-downloader.exe pwnedpasswords -s false`

### Download all NTLM hashes to a single txt file called `pwnedpasswords_ntlm.txt`
`haveibeenpwned-downloader.exe -n pwnedpasswords_ntlm`



## **Linux**


### Download all SHA1 hashes to a single txt file called `pwnedpasswords.txt` :
`haveibeenpwned-downloader pwnedpasswords`

### Download all SHA1 hashes to individual txt files into a custom directory called `hashes`:
`haveibeenpwned-downloader pwnedpasswords -s false`

### Download all NTLM hashes to a single txt file called `pwnedpasswords_ntlm.txt` : 
`haveibeenpwned-downloader -n pwnedpasswords_ntlm`



# Additional parameters

| Parameter   | Default value | Description |
|-------------|---------------|-------------|
| -s/--single | true | Determines whether to download hashes to a single file or as individual .txt files into another directory |
| -p/--parallelism | Same as `Environment.ProcessorCount * 8` | Determines how many hashes to download at a time |
| -o/--overwrite | false | Determines if output files should be overwritten or not |
| -n/--ntlm | false | When set, the downloader fetches NTLM hashes instead of SHA1 |
| -r/--resume | false | Resume from a previously interrupted download using checkpoint file |
| --max-retries | 5 | Maximum number of retry attempts for failed downloads before abandoning |
| --timeout | 30 | Timeout in seconds for each HTTP request |

# Additional usage examples
## Download all hashes to individual txt files into a custom directory called `hashes` using 64 threads to download the hashes
`haveibeenpwned-downloader.exe hashes -s false -p 64`
## Download all hashes to a single txt file called `pwnedpasswords.txt` using 64 threads, overwriting the file if it already exists
`haveibeenpwned-downloader.exe pwnedpasswords -o -p 64`
## Resume an interrupted download with custom retry settings
`haveibeenpwned-downloader.exe pwnedpasswords --resume --max-retries 10 --timeout 60`
## Download NTLM hashes with resume capability
`haveibeenpwned-downloader.exe pwnedpasswords_ntlm --ntlm --resume`

# Retry and Resume Features

The downloader includes robust retry and resume capabilities to handle network issues, server overload, and interruptions:

## Automatic Retry System

The downloader uses a **two-level retry strategy**:

1. **Polly Retry (Immediate)**: Handles transient failures automatically with exponential backoff and jitter
   - 5 retry attempts with progressive delays
   - Handles timeouts, network errors, and HTTP failures
   - No user intervention needed

2. **Custom Retry Queue (Persistent)**: Failed downloads after Polly retries are queued for later attempts
   - Progressive delays with jitter to avoid overwhelming the server
   - Configurable max retry attempts (default: 5)
   - Detailed logging of retry attempts

## Resume Capability

If your download is interrupted (network loss, system crash, or Ctrl+C), you can resume from where you left off:

```bash
# Start download
haveibeenpwned-downloader pwnedpasswords

# If interrupted, resume with:
haveibeenpwned-downloader pwnedpasswords --resume
```

### How Resume Works

- **Checkpoint File**: `{outputFile}.checkpoint.json` tracks all successfully downloaded hash ranges
- **Automatic Saving**: Checkpoint saved periodically (every 10,000 ranges) and on completion
- **Skip Completed**: On resume, already-downloaded ranges are automatically skipped
- **Clean Exit**: Checkpoint file is automatically deleted after successful completion

## Failed Downloads Tracking

If some hash ranges cannot be downloaded after all retry attempts:

- **Failed Downloads File**: `{outputFile}.failed.json` contains detailed information:
  - Hash index of failed range
  - Number of attempts made
  - Last error message
  - Timestamp of last attempt
  
- **Statistics**: Final output shows how many downloads failed and were abandoned
- **Analysis**: Use the failed downloads file to investigate problematic ranges

## Configuration Options

Customize retry behavior based on your network conditions:

```bash
# Increase retries for unstable connections
haveibeenpwned-downloader pwnedpasswords --max-retries 10

# Increase timeout for slow connections
haveibeenpwned-downloader pwnedpasswords --timeout 60

# Combine with resume for maximum reliability
haveibeenpwned-downloader pwnedpasswords --resume --max-retries 10 --timeout 60
```

## Output Files

When using the downloader, you may see the following files:

| File | Description | When Created |
|------|-------------|--------------|
| `{outputFile}.txt` | Downloaded password hashes | Always |
| `{outputFile}.checkpoint.json` | Resume data with completed ranges | During download |
| `{outputFile}.failed.json` | Failed downloads after all retries | If failures occur |

**Note**: Checkpoint files are automatically cleaned up after successful completion. Failed downloads files are kept for analysis.

# Performance and Reliability

## Improved Timeout Handling

- **Default timeout**: 30 seconds per HTTP request (configurable)
- **Smart retry logic**: Failed requests are retried with progressive delays
- **Parallel processing**: Multiple ranges downloaded concurrently with configurable parallelism

## Network Resilience

The downloader is designed to handle:
- ✅ Temporary network interruptions
- ✅ Server timeouts and overload (HTTP 503, 429)
- ✅ Connection resets and dropped connections
- ✅ Cloudflare rate limiting
- ✅ System crashes or forced termination

## Progress Tracking

During download, you'll see:
- Real-time progress bar with completion percentage
- Number of hash ranges downloaded
- Download speed (hashes per second)
- Cloudflare cache statistics
- Failed and abandoned download counts

