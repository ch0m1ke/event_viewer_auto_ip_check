import sys
import io
import unittest
from unittest.mock import patch
import ev_auto_ip_check

class testSaveIP (unittest.TestCase):
    def test_save_ip_success(self):
        ip_info = ["02/02/22 23:51:05", "192.168.1.123", "tcp/45824", "192.168.1.124", "tcp/4000"]
        counter = 1234
        destination_list = []
        self.assertTrue(ev_auto_ip_check.save_ip(ip_info[:], counter, destination_list))
    
    def test_save_ip_fail_ip_info_empty(self): # ip_info is empty
        ip_info = []
        counter = 1234
        destination_list = []
        self.assertFalse(ev_auto_ip_check.save_ip(ip_info, counter, destination_list))

    def test_save_ip_fail_ip_info_zero(self): # counter == 0
        ip_info = ["02/02/22 23:51:05", "192.168.1.123", "tcp/45824", "192.168.1.124", "tcp/4000"]
        counter = 0
        destination_list = []
        self.assertFalse(ev_auto_ip_check.save_ip(ip_info, counter, destination_list))

    def test_save_ip_fail_ip_info_less_than_zero(self): # counter < 0
        ip_info = ["02/02/22 23:51:05", "192.168.1.123", "tcp/45824", "192.168.1.124", "tcp/4000"]
        counter = -1
        destination_list = []
        self.assertFalse(ev_auto_ip_check.save_ip(ip_info, counter, destination_list))
    
    def test_save_ip_fail_destination_list_not_list(self): # destination_list is not a list
        ip_info = ["02/02/22 23:51:05", "192.168.1.123", "tcp/45824", "192.168.1.124", "tcp/4000"]
        counter = 1234
        destination_list = "this is a string"
        self.assertFalse(ev_auto_ip_check.save_ip(ip_info, counter, destination_list))
    
    def test_save_ip_fail_destination_list_not_list_again(self): # destination_list is not a list
        ip_info = ["02/02/22 23:51:05", "192.168.1.123", "tcp/45824", "192.168.1.124", "tcp/4000"]
        counter = 1234
        destination_list = 123
        self.assertFalse(ev_auto_ip_check.save_ip(ip_info, counter, destination_list))

class testMain (unittest.TestCase):
    def test_main_list_0(self):
        test_argvs = ["ev_auto_ip_check.py", "test_resources/fwcheck_list0.csv"]
        with patch.object(sys, "argv", test_argvs):
            capturedOutput = io.StringIO()              # Create StringIO object
            sys.stdout = capturedOutput                 # and redirect stdout.
            ev_auto_ip_check.main()                     # Call function.
            # sys.stdout = sys.__stdout__               # Reset redirect.
            captured_output = capturedOutput.getvalue() # Store stdout content in a variable
            test_output = '\x1b[92m\nThese are the suspicious IPs that need to be verified on the external/internal router:\n\nShort situation regarding the source IPs matching the search:\n\nSource IP: 224.123.12.34 is seen 3 times in file uploaded!\nSource IP: 141.18.123.204 is seen 2 times in file uploaded!\nSource IP: 222.138.6.204 is seen 2 times in file uploaded!\nSource IP: 212.218.244.153 is seen 1 times in file uploaded!\nSource IP: 222.152.249.172 is seen 1 times in file uploaded!\n\nDate of Event: 02/02/22 23:51:05\nSource IP: 224.123.12.34\nSource port: tcp/45824\nDestination IP: 192.14.165.221\nDestination port: tcp/23\n\nDate of Event: 02/02/22 23:50:37\nSource IP: 141.18.123.204\nSource port: tcp/46322\nDestination IP: 192.14.163.182\nDestination port: tcp/23\n\nDate of Event: 02/02/22 23:54:52\nSource IP: 222.138.6.204\nSource port: udp/1900\nDestination IP: 192.14.183.34\nDestination port: udp/8082\n\nDate of Event: 02/02/22 23:50:30\nSource IP: 212.218.244.153\nSource port: tcp/57150\nDestination IP: 192.14.161.118\nDestination port: tcp/23\n\nDate of Event: 02/02/22 23:52:43\nSource IP: 222.152.249.172\nSource port: tcp/24282\nDestination IP: 192.14.166.95\nDestination port: tcp/23\x1b[0m\n\x1b[93m\nText copied to clipboard!\x1b[0m\n'

            self.assertEqual(captured_output, test_output)
    
    def test_main_list_1(self):
        test_argvs = ["ev_auto_ip_check.py", "test_resources/fwcheck_list1.csv"]
        with patch.object(sys, "argv", test_argvs):
            capturedOutput = io.StringIO()              # Create StringIO object
            sys.stdout = capturedOutput                 # and redirect stdout.
            ev_auto_ip_check.main()                     # Call function.
            captured_output = capturedOutput.getvalue() # Store stdout content in a variable
            test_output = '\x1b[92m\nThese are the suspicious IPs that need to be verified on the external/internal router:\n\nShort situation regarding the source IPs matching the search:\n\nSource IP: 212.218.244.153 is seen 1 times in file uploaded!\nSource IP: 141.18.123.204 is seen 1 times in file uploaded!\n\nDate of Event: 02/02/22 23:50:30\nSource IP: 212.218.244.153\nSource port: tcp/57150\nDestination IP: 192.14.161.118\nDestination port: tcp/23\n\nDate of Event: 02/02/22 23:51:12\nSource IP: 141.18.123.204\nSource port: tcp/4549\nDestination IP: 192.14.169.36\nDestination port: tcp/5555\x1b[0m\n\x1b[93m\nText copied to clipboard!\x1b[0m\n'
            self.assertEqual(captured_output, test_output)
    
    def test_main_list_2(self):
        test_argvs = ["ev_auto_ip_check.py", "test_resources/fwcheck_list2.csv"]
        with patch.object(sys, "argv", test_argvs):
            capturedOutput = io.StringIO()              # Create StringIO object
            sys.stdout = capturedOutput                 # and redirect stdout.
            ev_auto_ip_check.main()                        # Call function.
            captured_output = capturedOutput.getvalue() # Store stdout content in a variable
            test_output = '\x1b[92m\nThese are the suspicious IPs that need to be verified on the external/internal router:\n\nShort situation regarding the source IPs matching the search:\n\nSource IP: 224.123.12.34 is seen 3 times in file uploaded!\nSource IP: 141.18.123.204 is seen 2 times in file uploaded!\nSource IP: 222.138.6.204 is seen 2 times in file uploaded!\nSource IP: 212.218.244.153 is seen 1 times in file uploaded!\nSource IP: 222.152.249.172 is seen 1 times in file uploaded!\n\nDate of Event: 02/02/22 23:51:05\nSource IP: 224.123.12.34\nSource port: tcp/45824\nDestination IP: 192.14.165.221\nDestination port: tcp/23\n\nDate of Event: 02/02/22 23:50:37\nSource IP: 141.18.123.204\nSource port: tcp/46322\nDestination IP: 192.14.163.182\nDestination port: tcp/23\n\nDate of Event: 02/02/22 23:54:52\nSource IP: 222.138.6.204\nSource port: udp/1900\nDestination IP: 192.14.183.34\nDestination port: udp/8082\n\nDate of Event: 02/02/22 23:50:30\nSource IP: 212.218.244.153\nSource port: tcp/57150\nDestination IP: 192.14.161.118\nDestination port: tcp/23\n\nDate of Event: 02/02/22 23:52:43\nSource IP: 222.152.249.172\nSource port: tcp/24282\nDestination IP: 192.14.166.95\nDestination port: tcp/23\x1b[0m\n\x1b[93m\nText copied to clipboard!\x1b[0m\n'
            self.assertEqual(captured_output, test_output)
    
    def test_main_list_3(self):
        test_argvs = ["ev_auto_ip_check.py", "test_resources/fwcheck_list3.csv"]
        with patch.object(sys, "argv", test_argvs):
            capturedOutput = io.StringIO()              # Create StringIO object
            sys.stdout = capturedOutput                 # and redirect stdout.
            ev_auto_ip_check.main()                     # Call function.
            captured_output = capturedOutput.getvalue() # Store stdout content in a variable
            test_output = '\x1b[91m\n[ERROR] No records found!\x1b[0m\n'
            self.assertEqual(captured_output, test_output)
    
    def test_main_list_4(self):
        test_argvs = ["ev_auto_ip_check.py", "test_resources/fwcheck_list4.csv"]
        with patch.object(sys, "argv", test_argvs):
            capturedOutput = io.StringIO()              # Create StringIO object
            sys.stdout = capturedOutput                 # and redirect stdout.
            ev_auto_ip_check.main()                     # Call function.
            captured_output = capturedOutput.getvalue() # Store stdout content in a variable
            test_output = '\x1b[91m\n[ERROR] The file is empty or corrupted!\x1b[0m\n'
            self.assertEqual(captured_output, test_output)
    
    def test_main_list_5(self):
        test_argvs = ["ev_auto_ip_check.py", "test_resources/fwcheck_list5.csv"]
        with patch.object(sys, "argv", test_argvs):
            capturedOutput = io.StringIO()              # Create StringIO object
            sys.stdout = capturedOutput                 # and redirect stdout.
            ev_auto_ip_check.main()                     # Call function.
            captured_output = capturedOutput.getvalue() # Store stdout content in a variable
            test_output = '\x1b[91m\n[ERROR] The file may be corrupted!\x1b[0m\n'
            self.assertEqual(captured_output, test_output)
    
    def test_main_list_6(self):
        test_argvs = ["ev_auto_ip_check.py", "test_resources/fwcheck_list6.csv"]
        with patch.object(sys, "argv", test_argvs):
            capturedOutput = io.StringIO()              # Create StringIO object
            sys.stdout = capturedOutput                 # and redirect stdout.
            ev_auto_ip_check.main()                     # Call function.
            captured_output = capturedOutput.getvalue() # Store stdout content in a variable
            test_output = '\x1b[91m\n[ERROR] The file may be corrupted!\x1b[0m\n'
            self.assertEqual(captured_output, test_output)
    
    def test_main_list_7(self):   
        test_argvs = ["ev_auto_ip_check.py", "test_resources/fwcheck_list7.csv"]
        with patch.object(sys, "argv", test_argvs):
            capturedOutput = io.StringIO()              # Create StringIO object
            sys.stdout = capturedOutput                 # and redirect stdout.
            ev_auto_ip_check.main()                     # Call function.
            captured_output = capturedOutput.getvalue() # Store stdout content in a variable
            test_output = '\x1b[91m\n[ERROR] The file may be corrupted!\x1b[0m\n'
            self.assertEqual(captured_output, test_output)
    
    def test_main_list_not_existing(self):
        test_argvs = ["ev_auto_ip_check.py", "test_resources/fwcheck_list8.csv"]
        with patch.object(sys, "argv", test_argvs):
            capturedOutput = io.StringIO()              # Create StringIO object
            sys.stdout = capturedOutput                 # and redirect stdout.
            ev_auto_ip_check.main()                     # Call function.
            sys.stdout = sys.__stdout__                 # Reset redirect.
            captured_output = capturedOutput.getvalue() # Store stdout content in a variable
            test_output = "\x1b[91m\n[ERROR] The file does't exist or can't be opened!\x1b[0m\n"
            self.assertEqual(captured_output, test_output)

if __name__ == '__main__':
    unittest.main()
