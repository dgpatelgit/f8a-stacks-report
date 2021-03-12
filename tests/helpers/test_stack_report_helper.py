"""Tests for classes from stack_report_helper module."""

from f8a_report.helpers.report_helper import ReportHelper, S3Helper
import pytest
from unittest import mock
import json

r = ReportHelper()
s = S3Helper()
emr_resp = {
    "ResponseMetadata": {
        "HTTPStatusCode": 200,
        "RequestId": "a336ee75-43f7-11e9-ad8b-83aeddb240c6",
        "RetryAttempts": 0,
        "HTTPHeaders": {
            "date": "Mon, 11 Mar 2019 12:17:27 GMT",
            "content-type": "application/x-amz-json-1.1", "content-length": "30",
            "x-amzn-requestid": "a336ee75-43f7-11e9-ad8b-83aeddb240c6"
        }
    },
    "JobFlowId": "j-LF2OPMVXAPQD"
}

mock_true = {
    "ingestion_details": {
        "a": "b"
    }
}

mock_false = {
    "ingestion_details": {}
}

unknown_json = {
    "npm@DELIM@lodash@DELIM@4.17.11": "true",
    "npm@DELIM@jquery@DELIM@3.3.1": "false",
    "npm@DELIM@jquery@DELIM@3.6.4": "false",
    "maven@DELIM@dep1@DELIM@4.17.11": "true",
    "maven@DELIM@dep2@DELIM@3.3.1": "false",
    "pypi@DELIM@dep2@DELIM@3.3.2": "false",
    "pypi@DELIM@dep1@DELIM@4.17.11": "true",
    "pypi@DELIM@dep2@DELIM@3.3.1": "false",
    "maven@DELIM@dep2@DELIM@3.6.4": "false"
}

latest_json = {
    "npm@DELIM@jquery": {
        "ecosystem": "npm",
        "name": "jquery",
        "known_latest_version": "3.6.3",
        "actual_latest_version": "3.6.4",
        "latest_non_cve_version": "3.6.4"
    },
    "npm@DELIM@lodash": {
        "ecosystem": "npm",
        "name": "lodash",
        "known_latest_version": "4.17.11",
        "actual_latest_version": "4.17.11"
    },
    "pypi@DELIM@dep2": {
        "ecosystem": "pypi",
        "name": "dep2",
        "known_latest_version": "3.3.1",
        "actual_latest_version": "3.3.2",
        "latest_non_cve_version": "3.3.2"
    },
    "pypi@DELIM@dep1": {
        "ecosystem": "pypi",
        "name": "dep1",
        "known_latest_version": "4.17.11",
        "actual_latest_version": "4.17.11"
    },
    "maven@DELIM@dep2": {
        "ecosystem": "maven",
        "name": "dep2",
        "known_latest_version": "3.3.1",
        "actual_latest_version": "3.6.4"
    },
    "maven@DELIM@dep1": {
        "ecosystem": "maven",
        "name": "dep1",
        "known_latest_version": "4.17.11",
        "actual_latest_version": "4.17.11"
    }

}

with open('tests/data/stacks_with_recurrence_count.json', 'r') as f:
    unique_stacks_with_recurrence_count = json.load(f)

with open('tests/data/collateddata.json', 'r') as f:
    collateddata = json.load(f)

with open('tests/data/stackdata.json', 'r') as f:
    stackdata = f.read()

with open('tests/data/stackdict.json', 'r') as f:
    stack_dict = json.load(f)

with open('tests/data/manifest.json', 'r') as f:
    manifest = json.load(f)

with open('tests/data/ingestiondata.json', 'r') as f:
    ingestiondata = f.read()
    ingestiondata = json.loads(ingestiondata)


def test_validate_and_process_date_success():
    """Test the success scenario of the function validate_and_process_date."""
    res = r.validate_and_process_date('2019-01-01')
    assert res == '2019-01-01'

    res = r.validate_and_process_date('1900-01-01')
    assert res == '1900-01-01'


def test_validate_and_process_date_no_real_dates():
    """Test the failure scenario of the function validate_and_process_date."""
    with pytest.raises(ValueError) as e:
        r.validate_and_process_date('2019-01-32')
        assert str(e.value) == 'Incorrect data format, should be YYYY-MM-DD'

    with pytest.raises(ValueError) as e:
        r.validate_and_process_date('0000-01-01')
        assert str(e.value) == 'Incorrect data format, should be YYYY-MM-DD'


def test_validate_and_process_date_failure():
    """Test the failure scenario of the function validate_and_process_date."""
    with pytest.raises(ValueError) as e:
        r.validate_and_process_date('xyzabc')
        assert str(e.value) == 'Incorrect data format, should be YYYY-MM-DD'

    with pytest.raises(ValueError) as e:
        r.validate_and_process_date('')
        assert str(e.value) == 'Incorrect data format, should be YYYY-MM-DD'


class MockPostgres:
    """Mock response object."""

    def execute(self, query):
        """Get the mock json response."""
        return query

    def fetchall(self):
        """Get the mock json response."""
        return stackdata


def test_retrieve_stack_analyses_ids():
    """Test retrieve stack data function."""
    r.cursor = MockPostgres()
    ids = ''.join(r.retrieve_stack_analyses_ids('2018-10-09', '2018-10-09'))
    assert ids is not None


def test_retrieve_stack_analyses_ids_wrong_dates():
    """Test the failure scenario of the function retrieve_stack_analyses_ids."""
    # both dates are incorrect
    with pytest.raises(ValueError) as e:
        r.retrieve_stack_analyses_ids('xyzabc', 'foobar')
        assert str(e.value) == 'Invalid date format'

    # start_date is incorrect
    with pytest.raises(ValueError) as e:
        r.retrieve_stack_analyses_ids('foobar', '2019-01-01')
        assert str(e.value) == 'Invalid date format'

    # start_date is incorrect
    with pytest.raises(ValueError) as e:
        r.retrieve_stack_analyses_ids('0000-01-01', '2019-01-01')
        assert str(e.value) == 'Invalid date format'

    # start_date is incorrect
    with pytest.raises(ValueError) as e:
        r.retrieve_stack_analyses_ids('2019-01-32', '2019-01-01')
        assert str(e.value) == 'Invalid date format'

    # end_date is incorrect
    with pytest.raises(ValueError) as e:
        r.retrieve_stack_analyses_ids('2019-01-01', 'foobar')
        assert str(e.value) == 'Invalid date format'

    # end_date is incorrect
    with pytest.raises(ValueError) as e:
        r.retrieve_stack_analyses_ids('2019-01-01', '2019-01-32')
        assert str(e.value) == 'Invalid date format'


def test_flatten_list_empty_input():
    """Test the success scenario of the function flatten_list."""
    assert r.flatten_list([]) == []
    assert r.flatten_list([[]]) == []


def test_flatten_list():
    """Test the success scenario of the function flatten_list."""
    assert r.flatten_list([[1]]) == [1]
    assert r.flatten_list([[1, 2]]) == [1, 2]
    assert r.flatten_list([[1, 2], [3, 4]]) == [1, 2, 3, 4]


def test_flatten_list_already_flat_list():
    """Test the success scenario of the function flatten_list."""
    with pytest.raises(TypeError) as e:
        r.flatten_list([1])
        assert e.value == "TypeError: 'int' object is not iterable"

    with pytest.raises(TypeError) as e:
        r.flatten_list([1, 2]) == [1, 2]
        assert e.value == "TypeError: 'int' object is not iterable"

    with pytest.raises(TypeError) as e:
        r.flatten_list([1, 2, 3, 4]) == [1, 2, 3, 4]
        assert e.value == "TypeError: 'int' object is not iterable"


def test_datediff_in_millisecs_same_dates():
    """Test the success scenario of the function datediff_in_millisecs."""
    start, end = '2018-08-23T17:05:52.912429', '2018-08-23T17:05:52.912429'
    assert r.datediff_in_millisecs(start, end) == 0


def test_datediff_in_millisecs():
    """Test the success scenario of the function datediff_in_millisecs."""
    start, end = '2018-08-23T17:05:52.0', '2018-08-23T17:05:53.1'
    # the difference is always zero or positive
    assert r.datediff_in_millisecs(start, end) == 100.0

    start, end = '2018-08-23T17:05:52.912429', '2018-08-23T17:05:53.624783'
    # the difference is always zero or positive
    assert r.datediff_in_millisecs(start, end) == 712.354


def test_datediff_in_millisecs_no_negative_result():
    """Test the success scenario of the function datediff_in_millisecs."""
    start, end = '2018-08-23T17:05:53.624783', '2018-08-23T17:05:52.912429'
    # the difference is always zero or positive
    assert r.datediff_in_millisecs(start, end) == 287.646


def test_datediff_in_millisecs_one_sec_change():
    """Test the success scenario of the function datediff_in_millisecs."""
    start, end = '2018-08-23T17:05:52.0', '2018-08-24T17:05:53.0'
    assert r.datediff_in_millisecs(start, end) == 0
    assert r.datediff_in_millisecs(end, start) == 0


def test_datediff_in_millisecs_one_day_change():
    """Test the success scenario of the function datediff_in_millisecs."""
    start, end = '2018-08-23T17:05:53.624783', '2018-08-24T17:05:53.624783'
    assert r.datediff_in_millisecs(start, end) == 0
    assert r.datediff_in_millisecs(end, start) == 0


def test_normalize_deps_list():
    """Test the success scenario of the function normalize_deps_list."""
    deps_list = [{'package': 'abc', 'version': '1.0.0'}]
    assert r.normalize_deps_list(deps_list) == ['abc 1.0.0']


def test_normalize_deps_list_empty_input():
    """Test the success scenario of the function normalize_deps_list."""
    deps_list = []
    assert r.normalize_deps_list(deps_list) == []


def test_normalize_deps_list_sorted():
    """Test the success scenario of the function normalize_deps_list."""
    deps_list = [{'package': 'abc', 'version': '1.0.0'},
                 {'package': 'zzz', 'version': '2.0.0'}]
    assert r.normalize_deps_list(deps_list) == ['abc 1.0.0', 'zzz 2.0.0']

    deps_list = [{'package': 'zzz', 'version': '1.0.0'},
                 {'package': 'abc', 'version': '2.0.0'}]
    assert r.normalize_deps_list(deps_list) == ['abc 2.0.0', 'zzz 1.0.0']


def test_populate_key_count_success():
    """Test the success scenario of the function populate_key_count."""
    assert (r.populate_key_count(['abc 1.0.0', 'xyz 1.0.0', 'abc 1.0.0']) ==
            {'abc 1.0.0': 2, 'xyz 1.0.0': 1})


def test_populate_key_count_failure():
    """Test the failure scenario of the function populate_key_count."""
    with pytest.raises(Exception) as e:
        r.populate_key_count([[], {}])
        assert e.value == 'TypeError("unhashable type: \'list\'",)'


@mock.patch('f8a_report.helpers.report_helper.S3Helper.store_json_content', return_value=True)
def test_store_training_data(_mock1):
    """Test the success scenario for storing Retraining Data in their respective buckets."""
    resp = r.store_training_data(collateddata)

    assert resp is None


@mock.patch('f8a_report.helpers.report_helper.S3Helper.store_json_content', return_value=True)
def test_store_training_data_loop(_mock1):
    """Test the count of calls to store to S3."""
    r.store_training_data(collateddata)
    assert _mock1.call_count == 3


def test_get_training_data_for_eco():
    """Test the generation of training data for npm."""
    resp = r.get_training_data_for_ecosystem(eco='npm', stack_dict=stack_dict)

    assert resp == manifest


@mock.patch('f8a_report.helpers.report_helper.S3Helper.store_json_content', return_value=True)
@mock.patch('f8a_report.helpers.report_helper.S3Helper.read_json_object', return_value=collateddata)
def test_collate_raw_data(_mock1, _mock2):
    """Test result collation success scenario."""
    result = r.collate_raw_data(unique_stacks_with_recurrence_count, 'weekly')

    assert result is not None


def mock_emr_api(*_args, **_kwargs):
    """Mock the call to the emr api service with status 200."""
    class MockResponse:
        """Mock response object."""

        def __init__(self, json_data, status_code):
            """Create a mock json response."""
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            """Return JSON data."""
            return self.json_data

    return MockResponse(emr_resp, 200)


def mock_emr_api_fail(*_args, **_kwargs):
    """Mock the call to the emr api service with status 400."""
    class MockResponse:
        """Mock response object."""

        def __init__(self, json_data, status_code):
            """Create a mock json response."""
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            """Return JSON data."""
            return self.json_data

    return MockResponse({}, 400)


@mock.patch('requests.post', side_effect=mock_emr_api)
def test_invoke_emr_api_success(_mock):
    """Test invoke emr api function with status 200."""
    result = r.invoke_emr_api('test-bucket', 'maven', '2019-01-03', 'http://github.com/test/test')

    assert result is None


@mock.patch('requests.post', side_effect=mock_emr_api_fail)
def test_invoke_emr_api_failure(_mock):
    """Test invoke emr api with status 400."""
    result = r.invoke_emr_api('test-bucket', 'maven', '2019-01-03', 'http://github.com/test/test')

    assert result is None


@mock.patch('f8a_report.helpers.report_helper.S3Helper.store_json_content',
            return_value=True)
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.collate_raw_data',
            return_value=collateddata)
@mock.patch('f8a_report.helpers.report_helper.UnknownDepsReportHelper.get_current_ingestion_status',
            return_value={'npm': {}, 'maven': {}, 'pypi': {}, 'golang': {}})
def test_normalize_worker_data(_mock1, _mock2, _mock3):
    """Test the success scenario of the function normalize_worker_data."""
    resp = r.normalize_worker_data('2018-10-10', '2018-10-18',
                                   stackdata, 'stack_aggregator_v2', 'weekly')

    assert resp is not None
    # Test whether summary for two stacks are reported
    assert resp[2]['stacks_summary']['total_stack_requests_count'] == 2

    # Test whether summary of a CVE is reported
    assert resp[2]['stacks_summary']['unique_cves']['CVE-2014-6393:4.3'] == 2

    # Test whether unknown licenses are reported
    assert resp[2]['stacks_summary']['unique_unknown_licenses_with_frequency']['mpl-2.0'] == 2


@mock.patch('f8a_report.helpers.report_helper.S3Helper.store_json_content', return_value=True)
@mock.patch('f8a_report.helpers.report_helper.UnknownDepsReportHelper.get_current_ingestion_status',
            return_value={'npm': {}, 'maven': {}, 'pypi': {}})
def test_normalize_worker_data_no_stack_aggregator(_mock_count, _mock2):
    """Test the success scenario of the function normalize_worker_data."""
    resp = r.normalize_worker_data('2018-10-10', '2018-10-18',
                                   stackdata, 'something_different_from_stack_aggregator',
                                   'weekly')

    assert resp is None


@mock.patch('f8a_report.helpers.report_helper.ReportHelper.retrieve_worker_results',
            return_value={'stack_aggregator_v2': 'val1'})
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.retrieve_stack_analyses_ids',
            return_value=['1'])
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.retrieve_ingestion_results',
            return_value=[mock_true, {}])
@mock.patch('f8a_report.helpers.sentry_report_helper.SentryReportHelper.retrieve_sentry_logs',
            return_value={})
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.create_venus_report',
            return_value={})
def test_get_report(_mock1, _mock2, _mock3, _mock4, _mock5):
    """Test success Get Report."""
    res, missing = r.get_report('2018-10-10', '2018-10-18')
    assert res is not None


@mock.patch('f8a_report.helpers.report_helper.ReportHelper.retrieve_worker_results',
            return_value=True)
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.retrieve_stack_analyses_ids',
            return_value=[])
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.retrieve_ingestion_results',
            return_value=[mock_false, {}])
@mock.patch('f8a_report.helpers.sentry_report_helper.SentryReportHelper.retrieve_sentry_logs',
            return_value={})
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.create_venus_report',
            return_value=True)
def test_get_report_negative_results(_mock1, _mock2, _mock3, _mock4, _mock5):
    """Test failure Get Report."""
    res, missing = r.get_report('2018-10-10', '2018-10-18')
    assert len(res) == 0


def test_retrieve_worker_results():
    """Test failure worker results."""
    res = r.retrieve_worker_results('2018-10-10', '2018-10-18', ['1', '2'], [])
    assert res == {}


@mock.patch('f8a_report.helpers.report_helper.S3Helper.store_json_content',
            return_value=True)
@mock.patch('f8a_report.helpers.report_helper.generate_report_for_unknown_epvs',
            return_value=unknown_json)
@mock.patch('f8a_report.helpers.report_helper.generate_report_for_latest_version',
            return_value=latest_json)
def test_normalize_ingestion_data(_mock1, _mock2, _mock3):
    """Test the success scenario of the function normalize_worker_data."""
    resp, missing = r.normalize_ingestion_data('2018-10-10', '2018-10-18', ingestiondata, 'daily')
    assert resp is not None


def test_get_trending():
    """Test top trending."""
    test_dict = {'a': 20, 'b': 2, 'c': 1, 'd': 100}
    res = r.get_trending(test_dict, 2)
    expected_output = {'d': 100, 'a': 20}
    assert (res == expected_output)


@mock.patch('f8a_report.helpers.report_helper.ReportHelper.retrieve_stack_analyses_ids',
            return_value=['1'])
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.retrieve_worker_results',
            return_value=True)
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.collate_and_retrain',
            return_value=True)
def test_re_train(_mock1, _mock2, _mock3):
    """Test success retrain."""
    resp = r.re_train('2018-10-10', '2018-10-18')
    assert resp is None


@mock.patch('f8a_report.helpers.report_helper.ReportHelper.save_result', return_value=True)
def test_create_venus_report(_mock1):
    """Test success create_venus_report."""
    resp = r.create_venus_report(['daily', '2019-09-26.json', {}])
    assert resp == {}


@mock.patch('f8a_report.helpers.report_helper.ReportHelper.collate_raw_data',
            return_value=collateddata)
@mock.patch('f8a_report.helpers.report_helper.ReportHelper.store_training_data',
            return_value=True)
def test_collate_and_retrain(_mock1, _mock2):
    """Test success create_venus_report."""
    resp = r.collate_and_retrain(unique_stacks_with_recurrence_count, 'weekly')
    assert resp is None
