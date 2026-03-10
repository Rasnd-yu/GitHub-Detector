# spoofed_contributor_core.py
"""
Spoofed Contributor Core Detection Logic - Detects fake top contributors in given repositories
"""

import requests
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional, Tuple
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AbuseEvidence:
    """Abuse evidence"""
    suspicious_contributor: str
    contributions: int
    reason: str
    contributor_info: Dict
    repo_info: Dict


class SpoofedContributorCoreDetector:
    """Spoofed contributor core detector"""

    def __init__(self, github_token: str, config: Dict):
        self.github_token = github_token
        self.config = config

        # Bot patterns to exclude
        self.bot_patterns = [
            r'bot$', r'^bot-', r'-bot$', r'\[bot\]$', r'\(bot\)$',
            r'github-actions', r'actions-user', r'dependabot', r'snyk-bot',
            r'renovate', r'greenkeeper', r'codecov', r'coveralls',
            r'auto', r'ci', r'test', r'build'
        ]

        # Prestigious organizations list
        self.prestigious_orgs = {
            'microsoft', 'google', 'facebook', 'apple', 'amazon', 'netflix',
            'twitter', 'uber', 'airbnb', 'spotify', 'apache', 'linux',
            'kubernetes', 'docker', 'mongodb', 'redis', 'nodejs', 'python',
            'golang', 'rust-lang', 'vuejs', 'angular', 'facebookresearch',
            'deepmind', 'openai', 'tensorflow', 'pytorch'
        }

        # Cache
        self.user_cache = {}
        self.top_contributors_cache = set()

        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        })

    def is_bot_account(self, username: str) -> bool:
        """Check if account is bot"""
        if not username:
            return False

        username_lower = username.lower()

        # Check against bot patterns
        for pattern in self.bot_patterns:
            if re.search(pattern, username_lower, re.IGNORECASE):
                return True

        # Additional bot indicators
        if any(x in username_lower for x in ['[bot]', '(bot)', '_bot', 'bot_']):
            return True

        return False

    def make_api_call(self, url: str, params: Dict = None) -> Optional[Dict]:
        """Safe API call"""
        max_retries = self.config.get('max_retries', 3)
        request_timeout = self.config.get('request_timeout', 30)
        rate_limit_delay = self.config.get('rate_limit_delay', 2.0)

        for attempt in range(max_retries):
            try:
                response = self.session.get(url, params=params, timeout=request_timeout)

                # Handle rate limiting
                if response.status_code == 403 and 'rate limit' in response.text.lower():
                    reset_time = response.headers.get('X-RateLimit-Reset', 0)
                    if reset_time:
                        wait_time = max(int(reset_time) - time.time(), 0) + 2
                        logger.warning(f"API rate limited, waiting {wait_time:.0f} seconds...")
                        time.sleep(wait_time)
                        continue

                if response.status_code == 200:
                    time.sleep(rate_limit_delay)
                    return response.json()
                elif response.status_code == 404:
                    return None
                else:
                    logger.error(f"API call failed: {response.status_code} - {response.text[:100]}")

            except requests.exceptions.RequestException as e:
                logger.error(f"Request exception: {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)

        return None

    def get_user_info(self, username: str) -> Optional[Dict]:
        """Get user information"""
        if username in self.user_cache:
            return self.user_cache[username]

        user_data = self.make_api_call(f"https://api.github.com/users/{username}")

        if user_data:
            self.user_cache[username] = user_data

        return user_data

    def is_top_contributor(self, username: str) -> bool:
        """Determine if user is top contributor"""
        if username in self.top_contributors_cache:
            return True

        user_data = self.get_user_info(username)
        if not user_data:
            return False

        # Skip bot accounts
        if self.is_bot_account(username):
            return False

        # Criterion 1: Many followers (influence metric)
        followers = user_data.get('followers', 0)
        min_followers = self.config.get('min_followers', 150)
        if followers > min_followers:
            self.top_contributors_cache.add(username)
            return True

        # Criterion 2: Member of prestigious organization
        orgs_data = self.make_api_call(f"https://api.github.com/users/{username}/orgs")

        if orgs_data:
            org_names = [org.get('login', '').lower() for org in orgs_data if org.get('login')]
            prestigious_org_membership = any(org in self.prestigious_orgs for org in org_names)

            if prestigious_org_membership:
                self.top_contributors_cache.add(username)
                return True

        # Criterion 3: Many public repositories
        min_public_repos = self.config.get('min_public_repos', 20)
        public_repos = user_data.get('public_repos', 0)
        if public_repos > min_public_repos:
            # Check for high-star projects
            repos_params = {'sort': 'stars', 'per_page': 5}
            top_repos = self.make_api_call(f"https://api.github.com/users/{username}/repos", repos_params)

            if top_repos:
                min_total_stars = self.config.get('min_total_stars', 500)
                total_stars = sum(repo.get('stargazers_count', 0) for repo in top_repos)
                if total_stars > min_total_stars:
                    self.top_contributors_cache.add(username)
                    return True

        return False

    def get_repository_contributors(self, owner: str, repo_name: str) -> List[Dict]:
        """Get repository contributors list"""
        try:
            max_contributors = self.config.get('max_contributors_per_repo', 30)
            params = {'per_page': max_contributors, 'anon': 'false'}

            url = f"https://api.github.com/repos/{owner}/{repo_name}/contributors"
            data = self.make_api_call(url, params)
            return data if data else []

        except Exception as e:
            logger.error(f"Failed to get contributors list: {e}")
            return []

    def analyze_repository(self, owner: str, repo_name: str) -> Tuple[bool, List[AbuseEvidence], float]:
        """
        Analyze if repository has spoofed contributor abuse

        Returns:
            Tuple[is_abuse, evidences, confidence]
        """
        repo_full_name = f"{owner}/{repo_name}"
        logger.info(f"Analyzing repository: {repo_full_name}")

        # Get repository information
        repo_info = self.make_api_call(f"https://api.github.com/repos/{repo_full_name}")
        if not repo_info:
            return False, [], 0.0

        # Get contributors
        contributors = self.get_repository_contributors(owner, repo_name)
        if not contributors:
            return False, [], 0.0

        # Detect spoofed contributors
        evidences = []

        for contributor in contributors:
            login = contributor.get('login', '')
            contributions = contributor.get('contributions', 0)

            # Skip bot accounts
            if self.is_bot_account(login):
                continue

            # Check if top contributor
            if self.is_top_contributor(login):
                user_info = self.get_user_info(login)

                # If top contributor but few contributions
                min_contributions = self.config.get('min_contributor_commits', 2)
                if contributions <= min_contributions:
                    # Calculate repository statistics
                    forks = repo_info.get('forks_count', 0)
                    stars = repo_info.get('stargazers_count', 0)
                    created_at = repo_info.get('created_at', '')

                    # Calculate repository age
                    repo_age_days = 0
                    if created_at:
                        try:
                            created_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                            repo_age_days = (datetime.now(timezone.utc) - created_date).days
                        except:
                            pass

                    # Decision criteria: small repository, new repository
                    max_repo_forks = self.config.get('max_repo_forks', 20)
                    max_repo_stars = self.config.get('max_repo_stars', 100)
                    min_repo_age_days = self.config.get('min_repo_age_days', 3000)

                    is_small_repo = (forks <= max_repo_forks and stars <= max_repo_stars)
                    is_recent_repo = repo_age_days < min_repo_age_days

                    if is_small_repo and is_recent_repo:
                        evidence = AbuseEvidence(
                            suspicious_contributor=login,
                            contributions=contributions,
                            reason=f"Top contributor '{login}' has only {contributions} commits in small/new repository",
                            contributor_info=user_info,
                            repo_info={
                                'forks': forks,
                                'stars': stars,
                                'age_days': repo_age_days
                            }
                        )
                        evidences.append(evidence)

        # Determine if abuse exists
        is_abuse = len(evidences) > 0

        # Calculate confidence
        if is_abuse:
            confidence = min(len(evidences) / len(contributors) * 2, 1.0)
        else:
            confidence = 0.0

        return is_abuse, evidences, confidence

    def detect_contributor_abuse(self, owner: str, repo_name: str) -> Tuple[bool, List[AbuseEvidence], float]:
        """Detect contributor abuse (main entry point)"""
        return self.analyze_repository(owner, repo_name)