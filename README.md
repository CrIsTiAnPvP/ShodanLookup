# ShodanLookUp

ShodanLookUp is a powerful Python-based tool for interacting with the Shodan API. It allows you to search for information about IP addresses and execute custom queries directly from your terminal. The tool features a user-friendly interactive mode with colorful output and a non-interactive CLI mode for scripting and automation.

![Banner](banner.png) <!-- Replace with an actual screenshot or banner image -->

## ✨ Features

- **Interactive & CLI Modes**: Use the intuitive interactive menu or the efficient command-line interface for your searches.
- **IP Address Lookup**: Get detailed information about a specific IP address, including location, ISP, open ports, and known vulnerabilities.
- **Custom Shodan Queries**: Perform complex searches using Shodan's query syntax and navigate through the results.
- **API Key Management**: The tool securely prompts for your Shodan API key and saves it in a `.env` file for future use.
- **Colored Output**: Results are presented in a clear, color-coded format for better readability.
- **Vulnerability Information**: Displays CVEs associated with services, including their CVSS score and a summary.

## 🚀 Getting Started

### Prerequisites

- Python 3.x
- A Shodan API Key. You can get one from [https://account.shodan.io/](https://account.shodan.io/).

### Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/CrIsTiAnPvP/ShodanLookup
    cd ShodanLookup
    ```

2. **Install dependencies:**
    It is recommended to use a virtual environment.

    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```

    Install the required Python packages from `requirements.txt`:

    ```bash
    pip install shodan colorama
    ```

    *(You may want to create a `requirements.txt` file for easier installation)*

### Configuration

The first time you run the tool in interactive mode, it will prompt you to enter your Shodan API key.

```bash
python main.py
```

The tool will validate the key and save it to a `.env` file in the project's root directory. This key will be used for all subsequent sessions.

## usage

You can run the tool in two modes: interactive or command-line (CLI).

### Interactive Mode

To start the interactive menu, simply run the script without any arguments:

```bash
python main.py
```

You will be presented with a menu to choose your action:

- **Search by IP address**: Get details for a single IP.
- **Search by Domain name**: (Feature to be implemented)
- **Search by query**: Use any Shodan search filter and navigate the results.

### Command-Line (CLI) Mode

For quick searches or scripting, you can use the command-line arguments.

**Arguments:**

- `-m, --mode`: The mode of operation.
  - `ip`: For an IP address search.
  - `query`: For a Shodan query search.
- `-t, --target`: The target for the search (either an IP address or a query string).

**Examples:**

- **Search for an IP address:**

    ```bash
    python main.py -m ip -t 8.8.8.8
    ```

- **Search using a query:**

    ```bash
    python main.py -m query -t "apache country:US"
    ```

## 📜 License

This project is licensed under the terms of the LICENSE file.

## ✍️ Author

- **CrIsTiiAnPvP**
