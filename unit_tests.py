from lm_rest_class import LogicMonitorREST
import os
from dotenv import load_dotenv
import unittest
from typing import List, Dict, Any
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestLogicMonitorREST(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        load_dotenv()
        cls.lm_rest = LogicMonitorREST(
            lm_info={
                'subdomain': os.getenv('PORTAL'),
                'bearer': os.getenv('BEARER')
            }
        )
        cls.test_results: List[Dict[str, Any]] = []

    def test_get_functions(self):
        """Test all GET functions in the LogicMonitorREST class."""
        # Dictionary of test functions and their required parameters
        test_cases = {
            'get_users': {'maxsize': 1},
            'get_user': {'id': 2},
            'get_alert_rules': {'maxsize': 1},
            # 'get_roles': {'maxsize': 1},
            'get_collectors': {'maxsize': 1},
            'get_collector_groups': {'maxsize': 1},
            # 'get_devices': {'maxsize': 1},
            # 'get_device_groups': {'maxsize': 1},
            'get_dashboards': {'maxsize': 1},
            'get_dashboard_groups': {'maxsize': 1},
            # 'get_report_groups': {'maxsize': 1},
            # 'get_websites': {'maxsize': 1},
            # 'get_website_groups': {'maxsize': 1},
            'get_alerts': {'maxsize': 1},
            'get_api_tokens': {'maxsize': 1},
            'get_appliesto_functions': {'maxsize': 1},
            'get_audit_logs': {'maxsize': 1},
            'get_access_groups': {'maxsize': 1},
            'get_config_sources': {'maxsize': 1},
            'get_datasources': {'maxsize': 1},
            'get_device_groups': {'maxsize': 1},
            'get_device_group': {'id': 1},
            'get_device_group_properties': {'id': 1},
            'get_device_group_property': {'id': 1, 'name': 'topo.namespace'},
            'get_device_group_datasources': {'id': 1, 'maxsize': 1},
        }

        for func_name, params in test_cases.items():
            with self.subTest(function=func_name):
                try:
                    # Get the function from the class
                    func = getattr(self.lm_rest, func_name)
                    
                    # Execute the function with parameters
                    logger.info(f"Testing {func_name}...")
                    result = func(**params)
                    
                    # Store test results
                    test_status = {
                        'function': func_name,
                        'status': 'SUCCESS',
                        'result_type': type(result).__name__,
                        'result_length': len(result) if isinstance(result, (list, dict)) else 'N/A',
                        'error': None
                    }
                    
                    # Verify the result
                    self.assertIsNotNone(result, f"{func_name} returned None")
                    if isinstance(result, list):
                        self.assertTrue(len(result) <= params.get('maxsize', float('inf')),
                                     f"{func_name} returned more items than maxsize")
                    
                    logger.info(f"✓ {func_name} test passed")
                    
                except Exception as e:
                    test_status = {
                        'function': func_name,
                        'status': 'FAILED',
                        'result_type': None,
                        'result_length': None,
                        'error': str(e)
                    }
                    logger.error(f"✗ {func_name} test failed: {str(e)}")
                    raise
                
                finally:
                    self.test_results.append(test_status)

    def tearDown(self):
        """Print test results after each test."""
        print("\nTest Results Summary:")
        print("-" * 80)
        print(f"{'Function':<30} {'Status':<10} {'Type':<15} {'Length':<10} {'Error'}")
        print("-" * 80)
        
        for result in self.test_results:
            print(
                f"{result['function']:<30} "
                f"{result['status']:<10} "
                f"{str(result['result_type']):<15} "
                f"{str(result['result_length']):<10} "
                f"{result['error'] if result['error'] else ''}"
            )

def run_tests():
    """Run all tests and return detailed results."""
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestLogicMonitorREST)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return test results
    return {
        'tests_run': result.testsRun,
        'errors': len(result.errors),
        'failures': len(result.failures),
        'skipped': len(result.skipped),
        'was_successful': result.wasSuccessful()
    }

if __name__ == '__main__':
    # Run tests and get results
    test_results = run_tests()
    
    # Print summary
    print("\nTest Execution Summary:")
    print("-" * 40)
    print(f"Total tests run: {test_results['tests_run']}")
    print(f"Errors: {test_results['errors']}")
    print(f"Failures: {test_results['failures']}")
    print(f"Skipped: {test_results['skipped']}")
    print(f"Success: {'Yes' if test_results['was_successful'] else 'No'}")