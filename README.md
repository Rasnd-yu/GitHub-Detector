# GitHub-Detector

GitHub-Detector is a comprehensive framework designed to detect and analyze various abuse behaviors on the GitHub platform. It leverages multiple detection modules to identify suspicious activities, such as fake stars, typo-squatting, reputation farming, and more.

## Features

- **Fake Stars Detection**: Identifies repositories with artificially inflated star counts.
- **Automatic Updates Detection**: Detects repositories with suspiciously frequent updates.
- **Typo-Squatting Detection**: Finds repositories with names similar to popular ones to prevent impersonation.
- **Reputation Farming Detection**: Analyzes user activity to detect attempts to gain reputation through suspicious means.
- **Fake Statistics Detection**: Identifies discrepancies in user or repository statistics.
- **Spoofed Contributor Detection**: Detects fake top contributors in repositories.
- **Issue Spam Detection**: Detects repositories or users involved in spamming issues by analyzing patterns of issue creation and content.
- **Keyword Stuffing Detection**: Identifies repositories or profiles that use excessive or irrelevant keywords to manipulate search results or visibility.

## Configuration

The framework uses a configuration file (`config.template.json`) to define detection parameters for each module. Users must replace placeholder values (e.g., `YOUR_GITHUB_TOKEN_X`) with their GitHub tokens to enable API access.

#### Example Configuration

```json
{
  "detection_configs": {
    "fake_stars": {
      "github_token": "YOUR_GITHUB_TOKEN_1",
      "detection_params": {
        "followers_threshold": 2,
        "following_threshold": 2,
        "repos_threshold": 5,
        "account_age_days": 730
      }
    }
  }
}
```

## Preparation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/GitHub-Detector.git
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure the `config.template.json` file with y our GitHub tokens and detection parameters.

## Running the Detector

GitHub-Detector supports two modes of operation:

#### Batch Detection Mode

In this mode, the detector processes multiple URLs from a CSV file. You can specify the input CSV file and the output file for results. In this project, the file "input_template.csv" is provided.

**Command Example:**

```bash
python github_abuse_detector.py --csv input.csv --output results.csv
```

- `--csv`: Path to the input CSV file containing URLs to analyze.
- `--output`: Path to the output CSV file where results will be saved (default: `output.csv`).

#### Single Detection Mode

In this mode, the detector analyzes a single URL for a specific category of abuse.

**Command Example:**

```bash
python github_abuse_detector.py --category fake_stars --url https://github.com/example/repo
```

- `--category`: The detection category (e.g., `fake_stars`, `typo_squatting`, etc.).
- `--url`: The URL of the repository or user to analyze.

#### Notes

If neither `--csv` nor `--category` and `--url` are provided, the program will run with the default parameters. When providing URLs, the reputation_farming and fake_stats categories require user URLs, while other categories require repository URLs.

## Requirements

- Python 3.8+
- GitHub API tokens with appropriate permissions
