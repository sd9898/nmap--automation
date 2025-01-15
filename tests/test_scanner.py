import unittest
from src.scanner import perform_scan, create_summary
from src.utils.utils import parse_nmap_output, format_scan_results

class TestScanner(unittest.TestCase):
    
    def test_perform_scan_basic(self):
        result = perform_scan('127.0.0.1', 'sS')  # Testing SYN scan
        self.assertIsNotNone(result)

    def test_perform_scan_udp(self):
        result = perform_scan('127.0.0.1', 'sU')  # Testing UDP scan
        self.assertIsNotNone(result)

    def test_create_summary(self):
        mock_results = {
            'basic': {
                'ports': {
                    'tcp': {
                        '80': {'state': 'open', 'service': 'http'},
                        '22': {'state': 'closed', 'service': 'ssh'}
                    }
                }
            }
        }
        summary = create_summary(mock_results)
        self.assertEqual(summary['total_open_ports'], 1)

    def test_parse_nmap_output(self):
        mock_output = "<NmapOutput>...</NmapOutput>"  # Replace with actual mock output
        parsed_data = parse_nmap_output(mock_output)
        self.assertIsInstance(parsed_data, dict)

    def test_format_scan_results(self):
        mock_results = {'open_ports': [80, 22]}
        formatted_results = format_scan_results(mock_results)
        self.assertIn("Formatted results", formatted_results)

if __name__ == '__main__':
    unittest.main()
