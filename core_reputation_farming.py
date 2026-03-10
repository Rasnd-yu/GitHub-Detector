"""
GitHub Reputation Farming Detector - Core Detection Module
Provides core detection functionality for github_abuse_detector.py
"""

import requests
import time
import logging
import re
import json
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AbuseEvidence:
    """Abuse behavior evidence"""
    user_name: str
    user_url: str
    repo_name: str
    repo_url: str
    target_url: str
    target_type: str  # 'pr' or 'issue'
    action_type: str  # 'approve', 'comment', 'review', 'merge'
    action_date: str
    content: Optional[str] = None
    suspicious_reason: str = ""
    pr_state: Optional[str] = None  # PR state: open, closed, merged
    pr_merged: Optional[bool] = None  # Whether PR was merged
    pr_age_days: int = 0  # Days from PR creation to activity
    days_after_resolution: int = 0  # Days after PR resolution (merge/close) to activity


class ReputationFarmingCoreDetector:
    """Reputation farming core detector - can be called externally"""

    def __init__(self, github_token: str, config: Dict = None):
        """Initialize detector"""
        self.github_token = github_token
        self.config = config or {}

        # Default configuration
        self.min_pr_age_days = self.config.get('min_pr_age_days', 400)
        self.max_prs_per_repo = self.config.get('max_prs_per_repo', 500)
        self.suspicious_activity_delay_days = self.config.get('suspicious_activity_delay_days', 400)
        self.post_resolution_delay_days = self.config.get('post_resolution_delay_days', 400)

        # Detection configuration
        self.suspicious_keywords = self.config.get('suspicious_keywords', [
            "+1", "LGTM", "looks good", "approved", "nice", "good job", "thanks",
            "great", "awesome", "excellent", "good work", "well done"
        ])
        self.min_comment_length = self.config.get('min_comment_length', 10)
        self.generic_patterns = self.config.get('generic_patterns', [
            "^[\\s\\W]*$",
            "^(good|nice|great|awesome|excellent)[\\s\\.,!]*$",
            "^\\+1[\\s\\W]*$",
            "^LGTM[\\s\\W]*$",
            "^thanks?[\\s\\.,!]*$",
            "^approved[\\s\\.,!]*$"
        ])

        # Excluded user list
        self.excluded_users = [
            'github-action[bot]', 'github-actions[bot]', 'dependabot[bot]',
            'codecov[bot]', 'pre-commit-ci[bot]', 'sonarcloud[bot]',
            'snyk-bot', 'renovate[bot]', 'mergify[bot]'
        ]

        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'GitHub-Reputation-Core-Detector/1.0'
        })
        if self.github_token:
            self.session.headers['Authorization'] = f'token {self.github_token}'

        # Cache
        self.user_cache = {}

    def make_api_call(self, url: str, params: Dict = None) -> Optional[Dict]:
        """Safe API call"""
        try:
            response = self.session.get(url, params=params, timeout=30)
            time.sleep(1.5)  # Avoid API rate limiting

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                logger.warning(f"API rate limited: {response.json().get('message', 'Unknown')}")
                time.sleep(60)
            elif response.status_code == 404:
                logger.debug(f"Resource not found: {url}")
            else:
                logger.error(f"API call failed {response.status_code}: {url}")

        except Exception as e:
            logger.error(f"API call exception {url}: {e}")

        return None

    def get_user_repositories(self, username: str) -> List[Dict]:
        """Get all repositories user participates in (own and contributed)"""
        repositories = []

        try:
            # 1. Get user's own repositories
            repos_url = f"https://api.github.com/users/{username}/repos"
            params = {'per_page': 100, 'sort': 'updated'}

            user_repos = self.make_api_call(repos_url, params)
            if user_repos:
                for repo in user_repos:
                    repositories.append({
                        'owner': repo['owner']['login'],
                        'name': repo['name'],
                        'full_name': repo['full_name'],
                        'is_owner': True
                    })

            # 2. Get repositories user contributed to (via PRs/Issues)
            search_url = "https://api.github.com/search/issues"
            query = f"involves:{username} type:pr created:>=2020-01-01"
            params = {'q': query, 'per_page': 50, 'sort': 'created'}

            search_data = self.make_api_call(search_url, params)
            if search_data and 'items' in search_data:
                for item in search_data['items']:
                    repo_url = item.get('repository_url', '')
                    if repo_url:
                        repo_match = re.search(r'repos/([^/]+)/([^/]+)$', repo_url)
                        if repo_match:
                            owner, repo = repo_match.group(1), repo_match.group(2)
                            repo_full_name = f"{owner}/{repo}"

                            # Deduplicate
                            if not any(r['full_name'] == repo_full_name for r in repositories):
                                repositories.append({
                                    'owner': owner,
                                    'name': repo,
                                    'full_name': repo_full_name,
                                    'is_owner': owner.lower() == username.lower()
                                })

            # Limit number to avoid excessive API calls
            max_repos = self.config.get('max_user_repos_to_scan', 100)
            repositories = repositories[:max_repos]

            logger.info(f"Found {len(repositories)} repositories for user {username}")

        except Exception as e:
            logger.error(f"Failed to get user repositories: {e}")

        return repositories

    def scan_repository(self, owner: str, repo: str, target_user: str = None) -> List[AbuseEvidence]:
        """Scan single repository, optionally for specific user"""
        logger.info(f"Scanning repository: {owner}/{repo}")
        evidences = []

        try:
            # Get old PRs
            old_prs = self._get_old_prs(owner, repo)

            for pr in old_prs[:self.max_prs_per_repo]:
                pr_evidences = self._analyze_pr_activity(owner, repo, pr, target_user)
                evidences.extend(pr_evidences)

        except Exception as e:
            logger.error(f"Error scanning repository {owner}/{repo}: {e}")

        return evidences

    def _get_old_prs(self, owner: str, repo: str) -> List[Dict]:
        """Get old PRs (with pagination support)"""
        cutoff_date = (datetime.now() - timedelta(days=self.min_pr_age_days)).strftime('%Y-%m-%d')

        all_prs = []
        page = 1
        max_results = self.config.get('max_prs_per_repo', 500)
        per_page = 100  # GitHub Search API max per page

        while len(all_prs) < max_results:
            url = "https://api.github.com/search/issues"
            params = {
                'q': f'repo:{owner}/{repo} is:pr created:<{cutoff_date}',
                'sort': 'created',
                'order': 'asc',
                'per_page': per_page,
                'page': page
            }

            data = self.make_api_call(url, params)
            if not data or 'items' not in data:
                break

            items = data['items']
            if not items:
                break

            all_prs.extend(items)

            # Check if more results exist
            total_count = data.get('total_count', 0)
            if len(items) < per_page or len(all_prs) >= min(total_count, max_results):
                break

            page += 1
            time.sleep(0.5)  # Avoid API rate limiting

            if page > 10:  # Safety limit, max 10 pages
                break

        logger.info(f"Found {len(all_prs)} old PRs in {owner}/{repo}")
        return all_prs[:max_results]

    def _analyze_pr_activity(self, owner: str, repo: str, pr: Dict, target_user: str = None) -> List[AbuseEvidence]:
        """Analyze activity on PR"""
        evidences = []
        pr_number = pr['number']

        try:
            # Get PR details
            pr_details = self.make_api_call(
                f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
            )
            if not pr_details:
                return []

            pr_merged = pr_details.get('merged', False)
            merge_date = pr_details.get('merged_at')

            # Parse dates
            pr_date = self._parse_github_datetime(pr['created_at'])
            resolution_date = pr_date

            if pr_merged and merge_date:
                resolution_date = self._parse_github_datetime(merge_date)

            # Get review records
            reviews_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"
            reviews = self.make_api_call(reviews_url, {'per_page': 30})

            if reviews:
                for review in reviews:
                    evidence = self._analyze_review(
                        review, owner, repo, pr, pr_date, resolution_date, pr_merged, target_user
                    )
                    if evidence:
                        evidences.append(evidence)

            # Get comments
            comments_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
            comments = self.make_api_call(comments_url, {'per_page': 30})

            if comments:
                for comment in comments:
                    evidence = self._analyze_comment(
                        comment, owner, repo, pr, pr_date, resolution_date, pr_merged, target_user
                    )
                    if evidence:
                        evidences.append(evidence)

        except Exception as e:
            logger.warning(f"Error analyzing PR #{pr_number}: {e}")

        return evidences

    def _parse_github_datetime(self, dt_str: str) -> datetime:
        """Parse GitHub datetime string"""
        if not dt_str:
            return None

        if dt_str.endswith('Z'):
            dt_str = dt_str.replace('Z', '+00:00')

        if '+' not in dt_str and '-' not in dt_str[-6:]:
            dt = datetime.fromisoformat(dt_str)
            return dt.replace(tzinfo=timezone.utc)
        else:
            return datetime.fromisoformat(dt_str)

    def _analyze_review(self, review: Dict, owner: str, repo: str, pr: Dict,
                        pr_date: datetime, resolution_date: datetime,
                        pr_merged: bool, target_user: str = None) -> Optional[AbuseEvidence]:
        """Analyze review record"""
        user = review.get('user', {})
        username = user.get('login', '')

        # Check if excluded user
        if self._is_excluded_user(username):
            return None

        # If target user specified, only focus on target user
        if target_user and username.lower() != target_user.lower():
            return None

        review_state = review.get('state', '')
        review_body = review.get('body', '')
        submitted_at = review.get('submitted_at', '')

        if not submitted_at:
            return None

        review_date = self._parse_github_datetime(submitted_at)
        if not review_date:
            return None

        # Calculate time differences
        days_from_creation = (review_date - pr_date).days if pr_date else 0
        days_after_resolution = (review_date - resolution_date).days if resolution_date else 0

        # Only focus on post-resolution activity
        if days_after_resolution <= 0:
            return None

        # Check if suspicious
        suspicious, reason = self._is_suspicious_activity(
            review_body, review_state, days_from_creation, days_after_resolution
        )

        if suspicious:
            return AbuseEvidence(
                user_name=username,
                user_url=user.get('html_url', ''),
                repo_name=f"{owner}/{repo}",
                repo_url=f"https://github.com/{owner}/{repo}",
                target_url=pr['html_url'],
                target_type='pr',
                action_type='approve' if review_state == 'APPROVED' else 'review',
                action_date=submitted_at,
                content=review_body[:200] if review_body else '',
                suspicious_reason=reason,
                pr_state='merged' if pr_merged else pr.get('state', 'open'),
                pr_merged=pr_merged,
                pr_age_days=days_from_creation,
                days_after_resolution=days_after_resolution
            )

        return None

    def _analyze_comment(self, comment: Dict, owner: str, repo: str, pr: Dict,
                         pr_date: datetime, resolution_date: datetime,
                         pr_merged: bool, target_user: str = None) -> Optional[AbuseEvidence]:
        """Analyze comment"""
        user = comment.get('user', {})
        username = user.get('login', '')

        # Check if excluded user
        if self._is_excluded_user(username):
            return None

        # If target user specified, only focus on target user
        if target_user and username.lower() != target_user.lower():
            return None

        comment_body = comment.get('body', '')
        created_at = comment.get('created_at', '')

        if not created_at:
            return None

        comment_date = self._parse_github_datetime(created_at)
        if not comment_date:
            return None

        # Calculate time differences
        days_from_creation = (comment_date - pr_date).days if pr_date else 0
        days_after_resolution = (comment_date - resolution_date).days if resolution_date else 0

        # Only focus on post-resolution activity
        if days_after_resolution <= 0:
            return None

        # Check if suspicious
        suspicious, reason = self._is_suspicious_activity(
            comment_body, None, days_from_creation, days_after_resolution
        )

        if suspicious:
            return AbuseEvidence(
                user_name=username,
                user_url=user.get('html_url', ''),
                repo_name=f"{owner}/{repo}",
                repo_url=f"https://github.com/{owner}/{repo}",
                target_url=comment.get('html_url', pr['html_url']),
                target_type='pr',
                action_type='comment',
                action_date=created_at,
                content=comment_body[:200] if comment_body else '',
                suspicious_reason=reason,
                pr_state='merged' if pr_merged else pr.get('state', 'open'),
                pr_merged=pr_merged,
                pr_age_days=days_from_creation,
                days_after_resolution=days_after_resolution
            )

        return None

    def _is_excluded_user(self, username: str) -> bool:
        """Check if user is excluded"""
        if not username:
            return True

        if username in self.excluded_users:
            return True

        if '[bot]' in username:
            return True

        return False

    def _is_suspicious_activity(self, content: str, state: str = None,
                                days_from_creation: int = 0,
                                days_after_resolution: int = 0) -> Tuple[bool, str]:
        """Check if activity is suspicious"""
        reasons = []

        # Check activity timing
        if days_from_creation > self.suspicious_activity_delay_days:
            reasons.append(f"Activity {days_from_creation} days after PR creation")

        if days_after_resolution > self.post_resolution_delay_days:
            reasons.append(f"Activity {days_after_resolution} days after PR resolution")

        # Check content
        is_generic, content_reason = self._is_generic_content(content)
        if is_generic:
            reasons.append(f"Generic content: {content_reason}")

        # Check approval status
        if state == 'APPROVED' and (not content or len(content.strip()) < self.min_comment_length):
            reasons.append("Simple approval without substantive comment")

        if reasons:
            return True, "; ".join(reasons)

        return False, ""

    def _is_generic_content(self, text: str) -> Tuple[bool, str]:
        """Check if content is generic/template"""
        if not text:
            return True, "Empty comment"

        text_lower = text.strip().lower()

        if len(text_lower) < self.min_comment_length:
            return True, f"Comment too short (less than {self.min_comment_length} characters)"

        # Check for keywords
        for keyword in self.suspicious_keywords:
            if keyword.lower() in text_lower:
                return True, f"Contains suspicious keyword: {keyword}"

        # Check regex patterns
        for pattern in self.generic_patterns:
            try:
                if re.match(pattern, text_lower, re.IGNORECASE):
                    return True, "Matches generic comment pattern"
            except re.error:
                continue

        return False, ""

    def detect_user_abuse(self, username: str) -> Tuple[bool, List[AbuseEvidence], float]:
        """
        Detect if user has reputation farming behavior

        Args:
            username: GitHub username

        Returns:
            tuple: (is_abuse, evidence_list, confidence)
        """
        logger.info(f"Starting reputation farming detection for user {username}")

        try:
            # 1. Get all repositories user participates in
            repositories = self.get_user_repositories(username)
            if not repositories:
                logger.warning(f"No repositories found for user {username}")
                return False, [], 0.0

            # 2. Scan each repository, focusing only on target user's activity
            all_evidences = []

            for i, repo in enumerate(repositories, 1):
                logger.info(f"Scanning progress: {i}/{len(repositories)} - {repo['full_name']}")

                evidences = self.scan_repository(
                    repo['owner'],
                    repo['name'],
                    target_user=username
                )
                all_evidences.extend(evidences)

                # Avoid API rate limiting
                if i % 3 == 0:
                    time.sleep(2)

            # 3. Determine if abuse exists
            is_abuse = len(all_evidences) > 0

            # 4. Calculate confidence
            confidence = self._calculate_confidence(all_evidences)

            logger.info(
                f"User {username} detection completed: abuse={is_abuse}, evidences={len(all_evidences)}, confidence={confidence:.2f}")

            return is_abuse, all_evidences, confidence

        except Exception as e:
            logger.error(f"Error detecting user {username}: {e}")
            return False, [], 0.0

    def _calculate_confidence(self, evidences: List[AbuseEvidence]) -> float:
        """Calculate confidence score"""
        if not evidences:
            return 0.0

        # Based on evidence count
        evidence_factor = min(len(evidences) / 10, 1.0)

        # Based on activity delay
        avg_delay = sum(e.days_after_resolution for e in evidences) / len(evidences)
        delay_factor = min(avg_delay / 1000, 1.0)

        # Based on PR age
        avg_pr_age = sum(e.pr_age_days for e in evidences) / len(evidences)
        age_factor = min(avg_pr_age / 2000, 1.0)

        # Combined confidence
        confidence = (evidence_factor * 0.4 + delay_factor * 0.3 + age_factor * 0.3)

        return min(confidence, 1.0)