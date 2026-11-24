from benchmarks.diagnose_audit_gap import reconcile


def row(rid=None, *, error=None, status=403):
    return dict(request_id=rid, decision_receipt={'sequence': 1} if rid else None,
                outcome_receipt={'sequence': 2} if rid else None,
                transport_error=error, http_status=status)


def ev(rid, seq, kind):
    return dict(request_id=rid, sequence=seq, event_type=kind)


def test_one_extra_pair_outside_http_responses():
    result = reconcile([row('a'), row(None, error='ReadTimeout', status=None)],
                       [ev('a',1,'DECISION'), ev('a',2,'OUTCOME'),
                        ev('b',3,'DECISION'), ev('b',4,'OUTCOME')])
    assert result['unmatched_audited_request_count'] == 1
    assert result['events_in_sequence_window'] == 4
    assert result['transport_errors'] == {'ReadTimeout': 1}
    assert result['unmatched_audited_requests'][0]['request_id'] == 'b'


def test_matching_receipts_and_audit():
    result = reconcile([row('a')], [ev('a',1,'DECISION'), ev('a',2,'OUTCOME')])
    assert not result['unmatched_audited_requests']
    assert not result['responses_missing_from_audit_window']
    assert not result['responses_with_nonstandard_audit_pairs']


def test_incomplete_audit_not_classified_as_complete():
    result = reconcile([row('a')], [ev('a',1,'DECISION')])
    assert result['responses_with_nonstandard_audit_pairs'] == {'a': ['DECISION']}
