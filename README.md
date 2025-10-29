# Hash Identifier

A modern, enhanced command-line tool for identifying hash types and cryptographic algorithms. This tool analyzes hash strings and provides intelligent suggestions about their possible algorithm types with confidence scoring.

## Features

- **Comprehensive Hash Detection** - Identifies 40+ hash types across multiple algorithm families
- **Confidence Scoring** - Intelligent algorithm to calculate match probability
- **Multiple Input Modes** - Single hash, batch file processing, or interactive mode
- **Category Organization** - Hashes grouped by family (MD, SHA, CMS, Database, etc.)
- **Visual Output** - Color-coded results with confidence bars for easy interpretation
- **Entropy Analysis** - Validates hash quality through character distribution analysis

## Supported Hash Types

### Checksum Algorithms
- CRC-16, CRC-16-CCITT, CRC-32, CRC-32B, ADLER-32

### MD Family
- MD2, MD4, MD5, MD5(HMAC), NTLM
- MD5(Unix), MD5(Wordpress), MD5(phpBB3), MD5(APR)

### SHA Family
- SHA-1, SHA-1(HMAC), SHA-224
- SHA-256, SHA-256(HMAC), SHA-256(Unix), SHA-256(Django)
- SHA-384, SHA-384(Django)
- SHA-512, SHA-512(HMAC)

### RIPEMD Family
- RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320

### Tiger Family
- Tiger-128, Tiger-160, Tiger-192

### Haval Family
- Haval-128, Haval-160, Haval-192, Haval-224, Haval-256

### Database & CMS
- MySQL5, MySQL 160bit
- Joomla, Wordpress, phpBB3

### Framework & System
- Django (SHA-1, SHA-256, SHA-384)
- DES(Unix)
- Windows SAM (LM_Hash:NT_Hash)

### Advanced
- Whirlpool

## Installation

### Prerequisites
- Python 3.6 or higher

### Clone the Repository
```bash
git clone https://github.com/yourusername/hash-identifier.git
cd hash-identifier
```

### Make Executable (Optional)
```bash
chmod +x hash_identifier.py
```

## Usage

### Single Hash Analysis
```bash
python hash_identifier.py 5d41402abc4b2a76b9719d911017c592
```

### Batch File Processing
```bash
python hash_identifier.py -f hashes.txt
```

### Interactive Mode
```bash
python hash_identifier.py
```

### Verbose Output
Show all possible matches including lower confidence results:
```bash
python hash_identifier.py -v 098f6bcd4621d373cade4e832627b4f6
```

### Additional Options
```bash
python hash_identifier.py --help           # Display help message
python hash_identifier.py --version        # Show version information
python hash_identifier.py --no-banner      # Suppress banner display
python hash_identifier.py --no-color       # Disable colored output
```

## Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `hash` | Hash string to identify (positional) |
| `-f, --file` | File containing hashes (one per line) |
| `-v, --verbose` | Show all possible matches with lower confidence |
| `--version` | Display version information |
| `--no-banner` | Suppress ASCII art banner |
| `--no-color` | Disable colored terminal output |

## Examples

### Example 1: MD5 Hash
```bash
python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
```

Output will show MD5 as the most likely match with high confidence.

### Example 2: SHA-256 Hash
```bash
python hash_identifier.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Example 3: Batch Processing
Create a file `hashes.txt`:
```
5d41402abc4b2a76b9719d911017c592
356a192b7913b04c54574d18c28d46e6395428ab
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Run:
```bash
python hash_identifier.py -f hashes.txt -v
```

## Output Interpretation

### Confidence Levels
- **High Confidence (70-100%)** - Green indicator, most likely matches
- **Medium Confidence (50-69%)** - Yellow indicator, possible matches
- **Low Confidence (<50%)** - Red indicator, less likely matches

### Visual Confidence Bar
The tool displays a visual bar representing the confidence percentage for each match, making it easy to assess the likelihood at a glance.

## How It Works

1. **Pattern Matching** - Compares input against known hash patterns using regex
2. **Length Validation** - Verifies hash length matches algorithm specifications
3. **Entropy Analysis** - Evaluates character distribution for hex-based hashes
4. **Confidence Calculation** - Scores matches based on pattern specificity and entropy
5. **Result Ranking** - Orders results by confidence score for optimal clarity

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Guidelines
- Follow PEP 8 style guidelines
- Add tests for new hash types
- Update documentation for new features
- Ensure backward compatibility

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by the classic hash-identifier tool
- Enhanced with modern Python practices and improved pattern recognition

## Support

If you encounter any issues or have questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Provide sample hashes and expected output when reporting bugs

## Changelog

### Version 2.0.0
- Complete rewrite with enhanced pattern recognition
- Added confidence scoring system
- Implemented entropy analysis
- Added batch processing support
- Improved visual output with color coding
- Added interactive mode
- Enhanced categorization system
