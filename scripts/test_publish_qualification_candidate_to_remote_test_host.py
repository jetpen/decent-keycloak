import unittest

from scripts.publish_qualification_candidate_to_remote_test_host import TARGET_IMAGE, select_latest_candidate


REPOSITORY = 'localhost/decent-keycloak-wallet-authenticator-spike'


class LatestCandidateSelectionTests(unittest.TestCase):
  def test_target_reference_is_the_requested_latest_tag(self):
    self.assertEqual(TARGET_IMAGE, 'decent-keycloak:latest')

  def test_selects_newest_valid_utc_candidate_tag(self):
    rows = [
        (REPOSITORY, 'qualification-candidate-20261031T032148Z'),
        (REPOSITORY, 'qualification-resolver-builder-20261031T041100Z'),
        (REPOSITORY, 'qualification-candidate-20261031T041100Z'),
        ('localhost/other-project', 'qualification-candidate-20261101T000000Z'),
        (REPOSITORY, 'qualification-candidate-not-a-timestamp'),
    ]
    self.assertEqual(
        select_latest_candidate(rows),
        REPOSITORY + ':qualification-candidate-20261031T041100Z')

  def test_refuses_when_no_candidate_exists(self):
    with self.assertRaisesRegex(RuntimeError, 'no qualification candidate image'):
      select_latest_candidate([(REPOSITORY, 'latest')])

  def test_refuses_ambiguous_latest_timestamp(self):
    with self.assertRaisesRegex(RuntimeError, 'ambiguous latest candidate timestamp'):
      select_latest_candidate([
          (REPOSITORY, 'qualification-candidate-20261031T041100Z'),
          (REPOSITORY, 'qualification-candidate-20261031T041100Z'),
      ])


if __name__ == '__main__':
  unittest.main()
