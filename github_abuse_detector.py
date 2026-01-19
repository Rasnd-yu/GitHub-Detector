import json
import re
import requests
import time
import csv
import base64
import logging
import joblib
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
from difflib import SequenceMatcher
from dataclasses import dataclass
from abc import ABC, abstractmethod
import warnings
from reputation_farming_core import ReputationFarmingCoreDetector, AbuseEvidence as RFAbuseEvidence
from spoofed_contributor_core import SpoofedContributorCoreDetector, AbuseEvidence as SCAbuseEvidence
from typo_squatting_core import TypoSquattingCoreDetector

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress sklearn version mismatch warnings
warnings.filterwarnings('ignore', category=UserWarning,
                        message='Trying to unpickle estimator')


@dataclass
class DetectionResult:
    """Detection result container"""
    sub_category: str
    url: str
    is_abuse: bool
    confidence: float  # 0.0-1.0
    details: Dict[str, Any]
    timestamp: str


class BaseDetector(ABC):
    """Base detector abstract class"""

    def __init__(self, config: Dict):
        self.config = config

        # Get detector-specific configuration
        detector_config = self._get_detector_config()
        self.github_token = detector_config['github_token']
        self.detection_params = detector_config['detection_params']
        self.api_settings = detector_config.get('api_settings', {})

        # Setup session
        self.session = requests.Session()
        user_agent = self.api_settings.get('user_agent',
                                           self.config['global_settings']['default_user_agent'])
        self.session.headers.update({
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': user_agent
        })
        if self.github_token:
            self.session.headers['Authorization'] = f'token {self.github_token}'

    def _get_detector_config(self) -> Dict:
        """Get detector-specific configuration"""
        sub_category = self.get_sub_category()
        return self.config['detection_configs'][sub_category]

    @abstractmethod
    def get_sub_category(self) -> str:
        """Return detector sub-category"""
        pass

    def make_api_call(self, url: str, params: Dict = None) -> Optional[Dict]:
        """Safe API call with retry logic"""
        # Use detector-specific API settings
        max_retries = self.api_settings.get('max_retries',
                                            self.config['global_settings']['default_max_retries'])
        request_timeout = self.api_settings.get('request_timeout',
                                                self.config['global_settings']['default_request_timeout'])
        rate_limit_delay = self.api_settings.get('rate_limit_delay',
                                                 self.config['global_settings']['default_rate_limit_delay'])

        for attempt in range(max_retries):
            try:
                response = self.session.get(url, params=params, timeout=request_timeout)

                # Handle rate limiting
                if response.status_code == 403 and 'rate limit' in response.text.lower():
                    reset_time = response.headers.get('X-RateLimit-Reset', 0)
                    if reset_time:
                        wait_time = max(int(reset_time) - time.time(), 0) + 2
                        logger.warning(f"Rate limited, waiting {wait_time:.0f} seconds...")
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

    def extract_repo_info(self, repo_url: str) -> Tuple[str, str]:
        """Extract repository information from URL"""
        repo_url = repo_url.rstrip('/').rstrip('.git')
        pattern = r"github\.com/([^/]+)/([^/?]+)"
        match = re.search(pattern, repo_url)
        if not match:
            raise ValueError(f"Invalid GitHub repository URL: {repo_url}")
        return match.group(1), match.group(2)

    def extract_user_info(self, user_url: str) -> str:
        """Extract user information from URL"""
        user_url = user_url.rstrip('/')
        pattern = r"github\.com/([^/?]+)"
        match = re.search(pattern, user_url)
        if not match:
            raise ValueError(f"Invalid GitHub user URL: {user_url}")
        return match.group(1)

    @abstractmethod
    def detect(self, url: str) -> DetectionResult:
        """Execute detection"""
        pass


class FakeStarsDetector(BaseDetector):
    """Fake stars detector"""

    def get_sub_category(self) -> str:
        return "fake_stars"

    def detect(self, url: str) -> DetectionResult:
        try:
            owner, repo_name = self.extract_repo_info(url)

            # Get stargazers information
            stargazers = self._get_stargazers(owner, repo_name)
            if not stargazers:
                return DetectionResult(
                    sub_category="fake_stars",
                    url=url,
                    is_abuse=False,
                    confidence=0.0,
                    details={"error": "No stargazers found"},
                    timestamp=datetime.now().isoformat()
                )

            # Detect fake stars
            fake_count = 0
            suspicious_users = []

            for star_info in stargazers:
                if self._is_fake_star(star_info):
                    fake_count += 1
                    suspicious_users.append({
                        "username": star_info["user"]["login"],
                        "followers": star_info["user"]["followers"]
                    })

            # Determine if abuse exists
            fake_percentage = fake_count / len(stargazers)
            is_abuse = fake_percentage > self.detection_params.get('fake_star_threshold', 0.1)

            return DetectionResult(
                sub_category="fake_stars",
                url=url,
                is_abuse=is_abuse,
                confidence=min(fake_percentage, 1.0),
                details={
                    "total_stars": len(stargazers),
                    "fake_stars": fake_count,
                    "fake_percentage": fake_percentage,
                    "suspicious_users": suspicious_users[:5]  # Show only top 5
                },
                timestamp=datetime.now().isoformat()
            )

        except Exception as e:
            logger.error(f"Fake stars detection failed: {e}")
            return DetectionResult(
                sub_category="fake_stars",
                url=url,
                is_abuse=False,
                confidence=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )

    def _get_stargazers(self, owner: str, repo_name: str) -> List[Dict]:
        """Get stargazers information"""
        stargazers = []
        page = 1
        per_page = self.detection_params.get('per_page', 30)
        max_stargazers = self.detection_params.get('max_stargazers_to_check', 100)

        while len(stargazers) < max_stargazers:
            url = f"https://api.github.com/repos/{owner}/{repo_name}/stargazers"
            params = {'page': page, 'per_page': per_page}

            data = self.make_api_call(url, params)
            if not data:
                break

            # Get user details
            for item in data:
                username = item.get('login') or item.get('user', {}).get('login')
                if not username:
                    continue

                user_info = self.make_api_call(f"https://api.github.com/users/{username}")
                if user_info:
                    star_info = {
                        "user": user_info,
                        "starred_at": item.get('starred_at', datetime.now().isoformat() + 'Z')
                    }
                    stargazers.append(star_info)

                if len(stargazers) >= max_stargazers:
                    break

            if len(data) < per_page:
                break

            page += 1

        return stargazers

    def _is_fake_star(self, star_info: Dict) -> bool:
        """Determine if a star is fake"""
        user = star_info["user"]

        try:
            create_time = datetime.fromisoformat(user['created_at'].replace('Z', '+00:00'))
            star_time = datetime.fromisoformat(star_info['starred_at'].replace('Z', '+00:00'))

            conditions = [
                user['followers'] < self.detection_params['followers_threshold'],
                user['following'] < self.detection_params['following_threshold'],
                user['public_repos'] < self.detection_params['repos_threshold'],
                (datetime.now(timezone.utc) - create_time).days < self.detection_params['account_age_days'],
                not user.get('email') if self.detection_params.get('check_email', True) else False,
                not user.get('bio') if self.detection_params.get('check_bio', True) else False,
                (star_time - create_time).days < self.detection_params['similar_star_time_days']
            ]

            satisfied = sum(conditions)
            return satisfied >= self.detection_params['fake_star_conditions']

        except Exception:
            return False


class AutomaticUpdatesDetector(BaseDetector):
    """Automatic updates detector"""

    def get_sub_category(self) -> str:
        return "automatic_updates"

    def detect(self, url: str) -> DetectionResult:
        try:
            owner, repo_name = self.extract_repo_info(url)

            # Get recent commits
            commits = self._get_recent_commits(owner, repo_name)

            if len(commits) < self.detection_params['min_commits']:
                return DetectionResult(
                    sub_category="automatic_updates",
                    url=url,
                    is_abuse=False,
                    confidence=0.0,
                    details={"total_commits": len(commits)},
                    timestamp=datetime.now().isoformat()
                )

            # Analyze commits
            total_changes = 0
            valid_commits = 0
            max_commits = self.detection_params.get('max_commits_to_check', 20)

            for commit in commits[:max_commits]:
                commit_details = self.make_api_call(
                    f"https://api.github.com/repos/{owner}/{repo_name}/commits/{commit['sha']}"
                )
                if commit_details:
                    stats = commit_details.get('stats', {})
                    total_changes += stats.get('additions', 0) + stats.get('deletions', 0)
                    valid_commits += 1

                time.sleep(self.detection_params.get('commit_delay_seconds', 0.1))

            avg_changes = total_changes / valid_commits if valid_commits > 0 else 0

            # Determine if abuse exists
            is_abuse = (len(commits) >= self.detection_params['min_commits'] and
                        avg_changes <= self.detection_params['max_avg_changes'])

            return DetectionResult(
                sub_category="automatic_updates",
                url=url,
                is_abuse=is_abuse,
                confidence=1.0 if is_abuse else 0.0,
                details={
                    "total_commits": len(commits),
                    "avg_changes": avg_changes,
                    "meets_min_commits": len(commits) >= self.detection_params['min_commits'],
                    "meets_max_changes": avg_changes <= self.detection_params['max_avg_changes']
                },
                timestamp=datetime.now().isoformat()
            )

        except Exception as e:
            logger.error(f"Automatic updates detection failed: {e}")
            return DetectionResult(
                sub_category="automatic_updates",
                url=url,
                is_abuse=False,
                confidence=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )

    def _get_recent_commits(self, owner: str, repo_name: str) -> List[Dict]:
        """Get recent commits within time window"""
        since_time = datetime.now(timezone.utc) - timedelta(hours=self.detection_params['time_window_hours'])
        since_str = since_time.isoformat().replace('+00:00', 'Z')

        url = f"https://api.github.com/repos/{owner}/{repo_name}/commits"
        params = {"since": since_str, "per_page": 100}

        data = self.make_api_call(url, params)
        return data if data else []


class TypoSquattingDetector(BaseDetector):
    """Typo squatting detector - using core detection module"""

    def get_sub_category(self) -> str:
        return "typo_squatting"

    def __init__(self, config: Dict):
        super().__init__(config)

        # Get detection parameters from config
        detection_params = self.detection_params

        # Core detector configuration
        core_config = {
            'min_stars_low': detection_params.get('min_stars_low', 0),
            'max_stars_low': detection_params.get('max_stars_low', 10),
            'min_stars_high': detection_params.get('min_stars_high', 100),
            'similarity_threshold': detection_params.get('similarity_threshold', 0.8),
            'min_fork_difference': detection_params.get('min_fork_difference', 10),
            'search_per_page': detection_params.get('search_per_page', 30),
            'similar_repo_check_count': detection_params.get('similar_repo_check_count', 5),
            'exclude_topics': detection_params.get('exclude_topics', ["template", "boilerplate"]),
            'max_retries': self.api_settings.get('max_retries', 3),
            'request_timeout': self.api_settings.get('request_timeout', 20),
            'rate_limit_delay': self.api_settings.get('rate_limit_delay', 2),
            'time_segments': detection_params.get('time_segments', 12),
            'start_date': detection_params.get('start_date', '2020-01-01'),
            'end_date': detection_params.get('end_date', '2024-12-31'),
            'max_workers': detection_params.get('max_workers', 3),
            'segment_by': detection_params.get('segment_by', 'month'),
            'max_search_results': detection_params.get('max_search_results', 1000),
            'max_repos_to_check': detection_params.get('max_repos_to_check', 100000)
        }

        # Create core detector
        self.core_detector = TypoSquattingCoreDetector(
            github_token=self.github_token,
            config=core_config
        )

    def detect(self, url: str) -> DetectionResult:
        """Detect typo squatting abuse"""
        try:
            owner, repo_name = self.extract_repo_info(url)

            # Use core detector for detection
            is_abuse, evidences, confidence = self.core_detector.detect_repository_abuse(owner, repo_name)

            # Generate detailed information
            details = self._generate_details(owner, repo_name, is_abuse, evidences, confidence)

            return DetectionResult(
                sub_category="typo_squatting",
                url=url,
                is_abuse=is_abuse,
                confidence=confidence,
                details=details,
                timestamp=datetime.now().isoformat()
            )

        except Exception as e:
            logger.error(f"Typo squatting detection failed: {e}")
            return DetectionResult(
                sub_category="typo_squatting",
                url=url,
                is_abuse=False,
                confidence=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )

    def _generate_details(self, owner: str, repo_name: str, is_abuse: bool,
                          evidences: List[Dict], confidence: float) -> Dict:
        """Generate detailed report"""
        repo_full_name = f"{owner}/{repo_name}"

        if not evidences:
            return {
                "repository": repo_full_name,
                "abuse_detected": False,
                "total_evidences": 0,
                "confidence": confidence,
                "message": "No typo squatting abuse detected"
            }

        # Prepare evidence details
        evidence_details = []
        for evidence in evidences:
            evidence_details.append({
                "similar_repo": evidence.get("similar_repo", ""),
                "similarity": evidence.get("similarity", 0.0),
                "current_stars": evidence.get("current_stars", 0),
                "similar_stars": evidence.get("similar_stars", 0),
                "star_ratio": evidence.get("similar_stars", 0) / max(evidence.get("current_stars", 1), 1),
                "abuse_reason": evidence.get("abuse_reason", "")
            })

        # Sort by similarity
        evidence_details_sorted = sorted(evidence_details, key=lambda x: x['similarity'], reverse=True)

        return {
            "repository": repo_full_name,
            "abuse_detected": True,
            "total_evidences": len(evidences),
            "confidence": confidence,
            "detection_strategy": "time-segmented-search",
            "detection_logic": "Using time-segmented search strategy to bypass GitHub API limits",
            "evidences": evidence_details_sorted[:3],  # Show top 3 evidences
            "highest_similarity": max(e.get("similarity", 0) for e in evidences),
            "avg_similarity": sum(e.get("similarity", 0) for e in evidences) / len(evidences) if evidences else 0,
            "time_segments_used": self.core_detector.config.get("time_segments", 12),
            "time_range": f"{self.core_detector.config.get('start_date', '')} to {self.core_detector.config.get('end_date', '')}",
            "summary": f"Found similarity with {len(evidences)} high-popularity repositories with same name"
        }


class ReputationFarmingDetector(BaseDetector):
    """Enhanced reputation farming detector - based on user PR history analysis"""

    def get_sub_category(self) -> str:
        return "reputation_farming"

    def __init__(self, config: Dict):
        super().__init__(config)

        # Get detection parameters from config
        detection_params = self.detection_params

        # Core detector configuration
        core_config = {
            'min_pr_age_days': detection_params.get('min_pr_age_days', 400),
            'max_prs_per_repo': detection_params.get('max_prs_per_repo', 500),
            'suspicious_activity_delay_days': detection_params.get('suspicious_activity_delay_days', 400),
            'post_resolution_delay_days': detection_params.get('post_resolution_delay_days', 400),
            'max_user_repos_to_scan': detection_params.get('max_user_repos_to_scan', 20),
            'suspicious_keywords': detection_params.get('suspicious_keywords', [
                "+1", "LGTM", "looks good", "approved", "nice", "good job", "thanks",
                "great", "awesome", "excellent", "good work", "well done"
            ]),
            'min_comment_length': detection_params.get('min_comment_length', 10),
            'generic_patterns': detection_params.get('generic_patterns', [
                "^[\\s\\W]*$",
                "^(good|nice|great|awesome|excellent)[\\s\\.,!]*$",
                "^\\+1[\\s\\W]*$",
                "^LGTM[\\s\\W]*$",
                "^thanks?[\\s\\.,!]*$",
                "^approved[\\s\\W]*$"
            ])
        }

        # Create core detector
        self.core_detector = ReputationFarmingCoreDetector(
            github_token=self.github_token,
            config=core_config
        )

    def detect(self, url: str) -> DetectionResult:
        """Detect reputation farming behavior"""
        try:
            # Extract username
            username = self.extract_user_info(url)

            # Use core detector for detection
            is_abuse, evidences, confidence = self.core_detector.detect_user_abuse(username)

            # Generate detailed information
            details = self._generate_details(username, is_abuse, evidences, confidence)

            return DetectionResult(
                sub_category="reputation_farming",
                url=url,
                is_abuse=is_abuse,
                confidence=confidence,
                details=details,
                timestamp=datetime.now().isoformat()
            )

        except Exception as e:
            logger.error(f"Reputation farming detection failed: {e}")
            return DetectionResult(
                sub_category="reputation_farming",
                url=url,
                is_abuse=False,
                confidence=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )

    def _generate_details(self, username: str, is_abuse: bool,
                          evidences: List[RFAbuseEvidence], confidence: float) -> Dict:
        """Generate detailed report"""

        if not evidences:
            return {
                "username": username,
                "abuse_detected": False,
                "total_evidences": 0,
                "confidence": confidence,
                "message": "No reputation farming detected"
            }

        # Statistics
        unique_repos = set(e.repo_name for e in evidences)

        # Sort evidence by time
        sorted_evidences = sorted(evidences, key=lambda x: x.pr_age_days, reverse=True)

        # Count by reason
        reason_counts = {}
        for evidence in evidences:
            reason = evidence.suspicious_reason
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

        # Prepare detailed evidence information
        evidence_details = []
        for i, evidence in enumerate(sorted_evidences[:5], 1):
            evidence_details.append({
                "repo": evidence.repo_name,
                "action_type": evidence.action_type,
                "action_date": evidence.action_date,
                "pr_age_days": evidence.pr_age_days,
                "days_after_resolution": evidence.days_after_resolution,
                "pr_state": evidence.pr_state,
                "content_preview": evidence.content[:100] + "..." if evidence.content else "",
                "suspicious_reason": evidence.suspicious_reason
            })

        return {
            "username": username,
            "abuse_detected": True,
            "total_evidences": len(evidences),
            "confidence": confidence,
            "unique_repositories": len(unique_repos),
            "repositories": list(unique_repos)[:10],
            "reason_breakdown": reason_counts,
            "detection_strategy": "user-centric-pr-history-analysis",
            "top_evidences": evidence_details,
            "avg_pr_age_days": sum(e.pr_age_days for e in evidences) // len(evidences) if evidences else 0,
            "avg_days_after_resolution": sum(e.days_after_resolution for e in evidences) // len(evidences) if evidences else 0
        }


class FakeStatsDetector(BaseDetector):
    """Fake statistics detector"""

    def get_sub_category(self) -> str:
        return "fake_stats"

    def __init__(self, config: Dict):
        super().__init__(config)

        # Regex patterns for matching
        self.user_star_patterns = [
            r'(?:my|total|github)\s+(?:stars?|⭐)\s*[:\-]?\s*(\d+[,.]?\d*[kKmM]?)',
            r'(\d+[,.]?\d*[kKmM]?)\s+(?:stars?|⭐)\s+(?:on|across|in)\s+github',
            r'github\s+stars?\s*[:\-]?\s*(\d+[,.]?\d*[kKmM]?)',
            r'total\s+stars?\s*[:\-]?\s*(\d+[,.]?\d*[kKmM]?)',
            r'⭐\s*(\d+[,.]?\d*[kKmM]?)\+?\s*(?:stars?)?',
            r'🌟\s*(\d+[,.]?\d*[kKmM]?)\+?\s*(?:stars?)?',
            r'stars?\s*[:\-]?\s*(\d+[,.]?\d*[kKmM]?)\+?',
            r'(?:i\s+have|i\'ve\s+got|i\s+got)\s+(\d+[,.]?\d*[kKmM]?)\s+stars?',
        ]

        self.repo_star_patterns = [
            r'(?:\[?[\w\-\.]+\/[\w\-\.]+\]?(?:\s*\([^)]+\))?|https?:\/\/github\.com\/[\w\-\.]+\/[\w\-\.]+)\s*[:\-]?\s*(\d+[,.]?\d*[kKmM]?)\s+stars?',
            r'(\d+[,.]?\d*[kKmM]?)\s+stars?\s*[:\-]\s*(?:\[?[\w\-\.]+\/[\w\-\.]+\]?|https?:\/\/github\.com\/[\w\-\.]+\/[\w\-\.]+)',
            r'\[([\w\-\.]+\/[\w\-\.]+)\]\([^)]+\)\s*[:\-]?\s*(\d+[,.]?\d*[kKmM]?)\s*(?:⭐|🌟|stars?)',
        ]

        self.stats_url_patterns = [
            r'github-readme-stats\.vercel\.app/api(?:\?[^"\'\)\s>]*)?',
            r'github-readme-stats\.vercel\.app(?:\?[^"\'\)\s>]*)?',
            r'github-readme-stats\.git\.app/api(?:\?[^"\'\)\s>]*)?',
            r'api\.github-readme-stats\.vercel\.app(?:\?[^"\'\)\s>]*)?',
            r'git\-stats\-readme\.vercel\.app(?:\?[^"\'\)\s>]*)?'
        ]

        self.compiled_user_star_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.user_star_patterns]
        self.compiled_repo_star_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.repo_star_patterns]
        self.compiled_stats_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.stats_url_patterns]

        # Profile repository keywords
        self.profile_repo_keywords = [
            'profile', 'home', 'homepage', 'personal'
        ]

    def detect(self, url: str) -> DetectionResult:
        """Detect fake statistics in user profile"""
        try:
            username = self.extract_user_info(url)

            # Find user's profile repository
            profile_repo = self._find_profile_repository(username)
            if not profile_repo:
                return DetectionResult(
                    sub_category="fake_stats",
                    url=url,
                    is_abuse=False,
                    confidence=0.0,
                    details={"error": "No profile repository found"},
                    timestamp=datetime.now().isoformat()
                )

            # Get README content
            readme_content = self._get_readme_content(profile_repo['full_name'])
            if not readme_content:
                return DetectionResult(
                    sub_category="fake_stats",
                    url=url,
                    is_abuse=False,
                    confidence=0.0,
                    details={"error": "No README content found"},
                    timestamp=datetime.now().isoformat()
                )

            # Get user's actual statistics
            actual_stars, actual_repos = self._get_user_actual_stats(username)

            # Detect fake user star claims
            fake_user_stars = self._extract_user_star_numbers(readme_content)

            # Detect fake repository star claims
            fake_repo_stars = []
            if self.detection_params.get('check_repo_stars', True):
                repo_star_claims = self._extract_repo_star_claims(readme_content)
                fake_repo_stars = self._verify_repo_star_claims(repo_star_claims, username)

            # Detect github-readme-stats usage
            stats_urls, username_mappings = self._extract_stats_urls_and_users(readme_content)
            github_stats_used = len(stats_urls) > 0

            # Detect if using someone else's statistics
            others_stats_detected = False
            if github_stats_used:
                for _, stats_username in username_mappings:
                    if stats_username.lower() != username.lower():
                        others_stats_detected = True
                        break

            # Determine if abuse exists
            is_abuse = False
            confidence = 0.0
            reasons = []

            # Fake user star detection
            if fake_user_stars:
                max_claimed = max([count for _, count in fake_user_stars])
                if max_claimed > actual_stars * self.detection_params.get('star_discrepancy_threshold', 5):
                    is_abuse = True
                    confidence = max(confidence, 0.7)
                    reasons.append(f"Fake user stars: claimed {max_claimed:,} vs actual {actual_stars:,}")

            # Fake repository star detection
            if fake_repo_stars:
                is_abuse = True
                confidence = max(confidence, 0.8)
                reasons.append(f"Fake repository stars: {len(fake_repo_stars)} repositories")

            # Using others' statistics detection
            if others_stats_detected:
                is_abuse = True
                confidence = max(confidence, 0.9)
                reasons.append("Using someone else's github-readme-stats data")

            # Calculate overall confidence
            if not is_abuse and github_stats_used:
                confidence = 0.1  # Normal usage but using stats

            return DetectionResult(
                sub_category="fake_stats",
                url=url,
                is_abuse=is_abuse,
                confidence=min(confidence, 1.0),
                details={
                    "username": username,
                    "profile_repo": profile_repo['full_name'],
                    "actual_stars": actual_stars,
                    "actual_repos": actual_repos,
                    "fake_user_stars": [f"{text}:{count}" for text, count in fake_user_stars],
                    "fake_repo_stars": fake_repo_stars,
                    "github_stats_used": github_stats_used,
                    "stats_urls_found": stats_urls[:3],
                    "others_stats_detected": others_stats_detected,
                    "reasons": reasons
                },
                timestamp=datetime.now().isoformat()
            )

        except Exception as e:
            logger.error(f"Fake statistics detection failed: {e}")
            return DetectionResult(
                sub_category="fake_stats",
                url=url,
                is_abuse=False,
                confidence=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )

    def _find_profile_repository(self, username: str) -> Optional[Dict]:
        """Find user's profile repository"""
        try:
            # Get user's repositories
            repos_url = f"https://api.github.com/users/{username}/repos"
            repos_data = self.make_api_call(repos_url, {
                'per_page': self.detection_params.get('max_profile_repos_to_check', 5),
                'sort': 'updated'
            })

            if not repos_data:
                return None

            # First check for username-named repository
            for repo in repos_data:
                if repo['name'].lower() == username.lower():
                    return {
                        "full_name": repo['full_name'],
                        "name": repo['name'],
                        "html_url": repo['html_url']
                    }

            # Check other possible profile repositories
            for repo in repos_data:
                repo_name = repo['name'].lower()
                for keyword in self.profile_repo_keywords:
                    if keyword in repo_name:
                        return {
                            "full_name": repo['full_name'],
                            "name": repo['name'],
                            "html_url": repo['html_url']
                        }

            return None

        except Exception as e:
            logger.error(f"Failed to find profile repository: {e}")
            return None

    def _get_readme_content(self, repo_full_name: str) -> Optional[str]:
        """Get repository's README content"""
        try:
            readme_url = f"https://api.github.com/repos/{repo_full_name}/readme"
            readme_data = self.make_api_call(readme_url)

            if not readme_data or 'content' not in readme_data:
                return None

            content = base64.b64decode(readme_data['content']).decode('utf-8', errors='ignore')
            return content

        except Exception as e:
            logger.error(f"Failed to get README content: {e}")
            return None

    def _get_user_actual_stats(self, username: str) -> Tuple[int, int]:
        """Get user's actual statistics"""
        try:
            user_url = f"https://api.github.com/users/{username}"
            user_data = self.make_api_call(user_url)

            if not user_data:
                return 0, 0

            # Get all user repositories to calculate total stars
            repos_url = f"https://api.github.com/users/{username}/repos"
            repos_data = self.make_api_call(repos_url, {
                'per_page': self.detection_params.get('max_user_repos_to_check', 50)
            })

            total_stars = 0
            if repos_data:
                total_stars = sum(repo.get('stargazers_count', 0) for repo in repos_data)

            total_repos = user_data.get('public_repos', 0)

            return total_stars, total_repos

        except Exception as e:
            logger.error(f"Failed to get user statistics: {e}")
            return 0, 0

    def _parse_star_count(self, star_text: str) -> int:
        """Parse star count text to number"""
        star_text = star_text.lower().replace(',', '')

        multiplier = 1
        if 'k' in star_text:
            multiplier = 1000
            star_text = star_text.replace('k', '')
        elif 'm' in star_text:
            multiplier = 1000000
            star_text = star_text.replace('m', '')

        try:
            number = float(star_text)
            return int(number * multiplier)
        except ValueError:
            return 0

    def _extract_user_star_numbers(self, text: str) -> List[Tuple[str, int]]:
        """Extract user star count claims from text"""
        found_stars = []

        for pattern in self.compiled_user_star_patterns:
            matches = pattern.findall(text)
            for match in matches:
                star_text = str(match)
                star_count = self._parse_star_count(star_text)
                if star_count >= self.detection_params.get('min_fake_stars', 100):
                    found_stars.append((star_text, star_count))

        return found_stars

    def _extract_repo_star_claims(self, text: str) -> List[Dict]:
        """Extract repository star claims from text"""
        repo_claims = []

        for pattern in self.compiled_repo_star_patterns:
            for match in pattern.finditer(text):
                try:
                    star_groups = [g for g in match.groups() if g]
                    if not star_groups:
                        continue

                    star_text = star_groups[0]
                    star_count = self._parse_star_count(star_text)

                    if star_count < self.detection_params.get('min_fake_stars', 100):
                        continue

                    match_text = match.group(0)
                    repo_name_match = re.search(r'\[?([\w\-\.]+/[\w\-\.]+)\]?', match_text)
                    if repo_name_match:
                        repo_full_name = repo_name_match.group(1)

                        if 'github.com/' in repo_full_name:
                            repo_full_name = repo_full_name.split('github.com/')[-1]

                        repo_claims.append({
                            "repo_full_name": repo_full_name,
                            "claimed_stars": star_count,
                            "star_text": star_text
                        })
                except Exception:
                    continue

        return repo_claims

    def _verify_repo_star_claims(self, repo_claims: List[Dict], username: str) -> List[Dict]:
        """Verify authenticity of repository star claims"""
        fake_repo_claims = []
        max_to_check = self.detection_params.get('max_repo_stars_to_check', 3)
        threshold = self.detection_params.get('repo_star_discrepancy_threshold', 5)

        for claim in repo_claims[:max_to_check]:
            try:
                repo_info = self.make_api_call(f"https://api.github.com/repos/{claim['repo_full_name']}")
                if repo_info:
                    actual_stars = repo_info.get('stargazers_count', 0)

                    if claim["claimed_stars"] > actual_stars * threshold:
                        fake_repo_claims.append({
                            **claim,
                            "actual_stars": actual_stars,
                            "discrepancy": claim["claimed_stars"] / max(actual_stars, 1)
                        })
                else:
                    # If repository doesn't exist but claims many stars, mark as suspicious
                    if claim["claimed_stars"] > 1000:
                        fake_repo_claims.append({
                            **claim,
                            "actual_stars": "unknown",
                            "discrepancy": "high"
                        })

                time.sleep(0.5)  # Avoid API rate limiting

            except Exception as e:
                logger.error(f"Failed to verify repository star claim: {e}")
                continue

        return fake_repo_claims

    def _extract_stats_urls_and_users(self, text: str) -> Tuple[List[str], List[Tuple[str, str]]]:
        """Extract github-readme-stats URLs and usernames from them"""
        import urllib.parse

        stats_urls = []
        username_mappings = []

        raw_matches = []
        for pattern in self.compiled_stats_patterns:
            for match in pattern.finditer(text):
                raw_matches.append(match.group(0))

        for raw_url in raw_matches:
            clean_url = raw_url

            if ')](http' in clean_url:
                clean_url = clean_url.split(')](http')[0]

            if clean_url.startswith('!['):
                clean_url = clean_url[2:]

            stats_urls.append(clean_url)

            username = self._extract_username_from_stats_url(clean_url)
            if username:
                username_mappings.append((clean_url, username))

        return stats_urls, username_mappings

    def _extract_username_from_stats_url(self, url: str) -> Optional[str]:
        """Extract username from github-readme-stats URL"""
        try:
            import urllib.parse

            clean_url = url.split(')')[0] if ')' in url else url
            clean_url = clean_url.split(']')[0] if ']' in clean_url else clean_url

            parsed_url = urllib.parse.urlparse(clean_url if '://' in clean_url else f'https://{clean_url}')
            query_params = urllib.parse.parse_qs(parsed_url.query)

            for param in ['username', 'user', 'login']:
                if param in query_params:
                    username = query_params[param][0]
                    username = username.split(')')[0] if ')' in username else username
                    username = username.split(']')[0] if ']' in username else username
                    return username

            return None

        except Exception as e:
            logger.error(f"Failed to parse URL {url}: {e}")
            return None


class SpoofedContributorDetector(BaseDetector):
    """Spoofed contributor detector - using core detection module"""

    def get_sub_category(self) -> str:
        return "spoofed_contributor"

    def __init__(self, config: Dict):
        super().__init__(config)

        # Get detection parameters from config
        detection_params = self.detection_params

        # Core detector configuration
        core_config = {
            'min_contributor_commits': detection_params.get('min_contributor_commits', 2),
            'max_repo_forks': detection_params.get('max_repo_forks', 20),
            'max_repo_stars': detection_params.get('max_repo_stars', 100),
            'min_repo_age_days': detection_params.get('min_repo_age_days', 3000),
            'min_followers': detection_params.get('min_followers', 150),
            'min_public_repos': detection_params.get('min_public_repos', 20),
            'min_total_stars': detection_params.get('min_total_stars', 500),
            'max_contributors_per_repo': detection_params.get('max_contributors_per_repo', 30),
            'max_retries': self.api_settings.get('max_retries', 3),
            'request_timeout': self.api_settings.get('request_timeout', 35),
            'rate_limit_delay': self.api_settings.get('rate_limit_delay', 2.0)
        }

        # Create core detector
        self.core_detector = SpoofedContributorCoreDetector(
            github_token=self.github_token,
            config=core_config
        )

    def detect(self, url: str) -> DetectionResult:
        """Detect spoofed contributors in repository"""
        try:
            owner, repo_name = self.extract_repo_info(url)

            # Use core detector for detection
            is_abuse, evidences, confidence = self.core_detector.detect_contributor_abuse(owner, repo_name)

            # Generate detailed information
            details = self._generate_details(owner, repo_name, is_abuse, evidences, confidence)

            return DetectionResult(
                sub_category="spoofed_contributor",
                url=url,
                is_abuse=is_abuse,
                confidence=confidence,
                details=details,
                timestamp=datetime.now().isoformat()
            )

        except Exception as e:
            logger.error(f"Spoofed contributor detection failed: {e}")
            return DetectionResult(
                sub_category="spoofed_contributor",
                url=url,
                is_abuse=False,
                confidence=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )

    def _generate_details(self, owner: str, repo_name: str, is_abuse: bool,
                          evidences: List[SCAbuseEvidence], confidence: float) -> Dict:
        """Generate detailed report"""
        repo_full_name = f"{owner}/{repo_name}"

        if not evidences:
            return {
                "repository": repo_full_name,
                "abuse_detected": False,
                "total_evidences": 0,
                "confidence": confidence,
                "message": "No spoofed contributor detected"
            }

        # Prepare evidence details
        evidence_details = []
        for evidence in evidences:
            evidence_details.append({
                "suspicious_contributor": evidence.suspicious_contributor,
                "contributions": evidence.contributions,
                "reason": evidence.reason,
                "contributor_followers": evidence.contributor_info.get('followers', 0),
                "contributor_repos": evidence.contributor_info.get('public_repos', 0),
                "repo_forks": evidence.repo_info.get('forks', 0),
                "repo_stars": evidence.repo_info.get('stars', 0),
                "repo_age_days": evidence.repo_info.get('age_days', 0)
            })

        # Sort by contribution count
        evidence_details_sorted = sorted(evidence_details, key=lambda x: x['contributions'])

        return {
            "repository": repo_full_name,
            "abuse_detected": True,
            "total_evidences": len(evidences),
            "confidence": confidence,
            "detection_strategy": "top-contributor-validation",
            "detection_logic": "Identify top contributors in repository and check if contributions are reasonable",
            "evidences": evidence_details_sorted[:5],  # Show top 5 evidences
            "top_contributors_found": len(set(e.suspicious_contributor for e in evidences)),
            "summary": f"Found {len(evidences)} top contributors with insufficient contributions in small/new repository"
        }


class IssueSpamDetector(BaseDetector):
    """Issue spam detector - enhanced version"""

    def __init__(self, config: Dict):
        super().__init__(config)

        # Load spam detection model with compatibility handling
        self.model = self._load_spam_model()
        self.model_loaded = self.model is not None

    def get_sub_category(self) -> str:
        return "issue_spam"

    def _load_spam_model(self):
        """Load spam detection model"""
        model_path = self.detection_params.get('model_path',
                                               'mlartifacts/2/0579ea92a6c7494e9bfdf42813fe3867/artifacts/nn/model.pkl')

        try:
            import pickle

            with open(model_path, 'rb') as f:
                model = pickle.load(f)

            logger.info(f"Spam detection model loaded successfully: {model_path}")
            return model
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return None

    def _prepare_issue_text(self, issue: Dict) -> str:
        """Prepare issue text for prediction"""
        title = issue.get("title", "")
        body = issue.get("body", "") or ""
        return f"{title} {body}".strip()

    def _fetch_repository_issues(self, owner: str, repo_name: str) -> List[Dict]:
        """Fetch all repository issues (no time limit)"""
        url = f"https://api.github.com/repos/{owner}/{repo_name}/issues"

        all_issues = []
        page = 1
        per_page = self.detection_params.get('per_page', 100)  # GitHub max 100 per page
        max_issues = self.detection_params.get('max_issues_to_check', 500)  # Increased to 500

        logger.info(f"Starting to fetch issues for repository {owner}/{repo_name}...")

        while len(all_issues) < max_issues:
            params = {
                "state": "all",  # Get all states
                "per_page": per_page,
                "page": page,
                "sort": "created",
                "direction": "desc"  # From newest to oldest
            }

            # 🔥 Key modification: No time restriction, get all issues

            try:
                data = self.make_api_call(url, params)
                if not data:
                    logger.warning(f"No data on page {page}, stopping fetch")
                    break

                # Filter out pull requests
                real_issues = []
                for issue in data:
                    if "pull_request" not in issue:
                        real_issues.append(issue)

                all_issues.extend(real_issues)
                logger.info(f"Page {page}: Found {len(real_issues)} issues, total {len(all_issues)}")

                # Check if more issues exist
                if len(data) < per_page:
                    logger.info(f"All issues fetched, total {len(all_issues)}")
                    break

                page += 1

                # Reasonable delay strategy
                if page % 10 == 0:  # Rest every 10 pages
                    time.sleep(2)
                else:
                    time.sleep(self.detection_params.get('fetch_delay_seconds', 0.8))

                # GitHub API pagination protection
                if page > 100:  # GitHub limits to 100 pages
                    logger.warning(f"Reached GitHub API pagination limit (100 pages), stopping fetch")
                    break

            except Exception as e:
                logger.error(f"Failed to fetch issues on page {page}: {e}")
                break

        logger.info(f"Total issues fetched: {len(all_issues)}")
        return all_issues[:max_issues]

    def detect(self, url: str) -> DetectionResult:
        """Detect issue spam in repository - zero tolerance strategy"""
        try:
            owner, repo_name = self.extract_repo_info(url)

            # Check if model loaded successfully
            if not self.model_loaded:
                return DetectionResult(
                    sub_category="issue_spam",
                    url=url,
                    is_abuse=False,
                    confidence=0.0,
                    details={"error": "Spam detection model not loaded"},
                    timestamp=datetime.now().isoformat()
                )

            # Get all issues (no time restriction)
            issues = self._fetch_repository_issues(owner, repo_name)

            if len(issues) == 0:
                return DetectionResult(
                    sub_category="issue_spam",
                    url=url,
                    is_abuse=False,
                    confidence=0.0,
                    details={
                        "total_issues": 0,
                        "reason": "No issues found in repository"
                    },
                    timestamp=datetime.now().isoformat()
                )

            logger.info(f"Starting detection for {len(issues)} issues...")

            # 🔥 Zero tolerance strategy: Any spam issue marks as abuse
            spam_issues = []
            spam_probabilities = []

            # Process in batches to avoid memory issues
            batch_size = 50
            processed_count = 0

            for i in range(0, len(issues), batch_size):
                batch = issues[i:i + batch_size]

                for issue in batch:
                    try:
                        issue_text = self._prepare_issue_text(issue)
                        if not issue_text or len(issue_text.strip()) < 5:
                            continue

                        # Predict, probabilities[0] is not-spam probability
                        prediction = self.model.predict([issue_text])[0]
                        probabilities = self.model.predict_proba([issue_text])[0]

                        # Model output: 0=not-spam, 1=spam
                        is_spam = prediction == 'spam'
                        spam_probability = probabilities[1]

                        if is_spam:
                            spam_issues.append({
                                "id": issue["id"],
                                "title": issue["title"][:80] + "..." if len(issue["title"]) > 80 else issue["title"],
                                "spam_probability": float(spam_probability),
                                "url": issue.get("html_url", ""),
                                "created_at": issue.get("created_at", ""),
                                "state": issue.get("state", "unknown")
                            })
                            spam_probabilities.append(spam_probability)

                    except Exception as e:
                        logger.warning(f"Failed to predict issue {issue.get('id')}: {e}")
                        continue

                processed_count += len(batch)
                logger.info(f"Processed {processed_count}/{len(issues)} issues, found {len(spam_issues)} spam")

                # Batch delay
                time.sleep(0.5)

            # 🔥 Decision logic: Any spam issue means abuse
            is_abuse = len(spam_issues) > 0

            # Confidence calculation
            if is_abuse:
                if spam_probabilities:
                    # Use highest spam probability as confidence, considering count
                    max_prob = max(spam_probabilities)
                    count_factor = min(len(spam_issues) / 10, 1.0)  # Max consider 10 spam issues
                    confidence = min(max_prob * 0.7 + count_factor * 0.3, 1.0)
                else:
                    confidence = 0.9  # Default high confidence
            else:
                confidence = 0.0

            # Sort by spam probability
            spam_issues_sorted = sorted(spam_issues, key=lambda x: x['spam_probability'], reverse=True)

            # Calculate statistics
            total_issues = len(issues)
            spam_count = len(spam_issues)
            spam_ratio = spam_count / total_issues if total_issues > 0 else 0

            return DetectionResult(
                sub_category="issue_spam",
                url=url,
                is_abuse=is_abuse,
                confidence=confidence,
                details={
                    "total_issues": total_issues,
                    "spam_count": spam_count,
                    "spam_ratio": f"{spam_ratio:.3f}",
                    "zero_tolerance": True,
                    "policy": "Any spam issue → Abuse",
                    "highest_spam_probability": max(spam_probabilities) if spam_probabilities else 0.0,
                    "avg_spam_probability": sum(spam_probabilities) / len(
                        spam_probabilities) if spam_probabilities else 0.0,
                    "spam_issues": spam_issues_sorted[:5],  # Show top 5 most suspicious
                    "all_spam_count": spam_count
                },
                timestamp=datetime.now().isoformat()
            )

        except Exception as e:
            logger.error(f"Issue spam detection failed: {e}")
            return DetectionResult(
                sub_category="issue_spam",
                url=url,
                is_abuse=False,
                confidence=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )


class KeywordStuffingDetector(BaseDetector):
    """Keyword stuffing detector based on BM25 algorithm"""

    def get_sub_category(self) -> str:
        return "keyword_stuffing"

    def __init__(self, config: Dict):
        super().__init__(config)

        # Store all repository README contents for building BM25 corpus
        self.all_readmes = []
        self.all_readme_repos = []

        # Use rank_bm25 library
        from rank_bm25 import BM25Okapi

        self.BM25Okapi = BM25Okapi
        self.bm25_model = None
        self.corpus_ready = False

    def _clean_text(self, text: str) -> str:
        """Clean text, remove Markdown, HTML tags, etc."""
        if not text:
            return ""

        # Remove HTML tags
        text = re.sub(r'<.*?>', '', text)

        # Remove Markdown markers
        text = re.sub(r'[#*`~_\[\]()]', '', text)

        # Remove extra spaces
        text = re.sub(r'\s+', ' ', text)

        return text.strip()

    def _improved_tokenize(self, text: str) -> List[str]:
        """Improved tokenization function"""
        if not text:
            return []

        # Convert to lowercase
        text = text.lower()

        # Remove punctuation but keep hyphens and underscores
        text = re.sub(r'[^\w\s-]', ' ', text)

        # Tokenize
        words = text.split()

        # Filter stop words
        stop_words = {'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was',
                      'were', 'be', 'been', 'being', 'a', 'an', 'this', 'that', 'these', 'those', 'it', 'as', 'from',
                      'not', 'has', 'have'}

        filtered_words = []
        for word in words:
            if len(word) <= 2:
                continue

            # Process hyphen-connected words
            if '-' in word:
                subwords = [sw for sw in word.split('-') if len(sw) > 2]
                filtered_words.extend(subwords)
            elif '_' in word:
                subwords = [sw for sw in word.split('_') if len(sw) > 2]
                filtered_words.extend(subwords)
            elif word not in stop_words:
                filtered_words.append(word)

        return filtered_words

    def _get_repo_keywords(self, owner: str, repo_name: str) -> List[str]:
        """Get repository keywords (GitHub topics)"""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo_name}/topics"

            # Need specific Accept header for topics
            headers = self.session.headers.copy()
            headers["Accept"] = "application/vnd.github.mercy-preview+json"

            response = self.session.get(url, headers=headers, timeout=self.api_settings.get('request_timeout', 30))

            if response.status_code == 200:
                data = response.json()
                return data.get('names', [])
            else:
                logger.warning(f"Failed to get keywords: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Exception getting keywords: {e}")
            return []

    def _get_readme_content(self, owner: str, repo_name: str) -> Optional[str]:
        """Get README content"""
        try:
            readme_url = f"https://api.github.com/repos/{owner}/{repo_name}/readme"
            readme_data = self.make_api_call(readme_url)

            if not readme_data or 'content' not in readme_data:
                return None

            content = base64.b64decode(readme_data['content']).decode('utf-8', errors='ignore')
            cleaned_content = self._clean_text(content)
            return cleaned_content

        except Exception as e:
            logger.error(f"Failed to get README content: {e}")
            return None

    def _build_bm25_corpus(self, repos: List[Dict]) -> None:
        """Build BM25 corpus"""
        logger.info(f"Starting to build BM25 corpus with {len(repos)} repositories")

        valid_docs = []
        valid_repos = []

        for repo_info in repos:
            try:
                owner = repo_info['owner']
                repo_name = repo_info['name']
                repo_full_name = f"{owner}/{repo_name}"

                # Get README content
                readme_content = self._get_readme_content(owner, repo_name)

                if readme_content and len(readme_content) > 100:  # Ensure sufficient content
                    valid_docs.append(readme_content)
                    valid_repos.append(repo_full_name)

                # Avoid API rate limiting
                time.sleep(0.3)

            except Exception as e:
                logger.warning(f"Failed to process repository {repo_info}: {e}")
                continue

        # Tokenize corpus
        tokenized_corpus = [self._improved_tokenize(doc) for doc in valid_docs]

        # Keep only documents with actual content
        filtered_docs = []
        filtered_repos = []
        for i, tokens in enumerate(tokenized_corpus):
            if tokens and len(tokens) > 10:  # Ensure sufficient tokens
                filtered_docs.append(tokens)
                filtered_repos.append(valid_repos[i])

        # Create BM25 model
        if filtered_docs:
            self.bm25_model = self.BM25Okapi(filtered_docs)
            self.all_readmes = filtered_docs
            self.all_readme_repos = filtered_repos
            self.corpus_ready = True
            logger.info(f"BM25 corpus built: {len(filtered_docs)} valid documents")
        else:
            logger.warning("Not enough valid documents to build corpus")

    def _calculate_bm25_scores(self, repo_full_name: str, keywords: List[str],
                               readme_content: str) -> List[Dict]:
        """Calculate BM25 scores for keywords"""
        if not self.corpus_ready or not keywords or not readme_content:
            return []

        # Find current repository index in corpus
        try:
            repo_index = self.all_readme_repos.index(repo_full_name)
        except ValueError:
            # If current repository not in corpus, add it
            tokenized_doc = self._improved_tokenize(readme_content)
            if tokenized_doc and len(tokenized_doc) > 10:
                # Add new document and rebuild model
                self.all_readmes.append(tokenized_doc)
                self.all_readme_repos.append(repo_full_name)
                self.bm25_model = self.BM25Okapi(self.all_readmes)
                repo_index = len(self.all_readmes) - 1
            else:
                return []

        # Calculate score for each keyword
        keyword_scores = []

        for keyword in keywords:
            # Tokenize keyword
            keyword_tokens = self._improved_tokenize(keyword.replace('-', ' ').replace('_', ' '))

            if not keyword_tokens:
                keyword_scores.append({
                    "keyword": keyword,
                    "score": 0.0,
                    "tokens": []
                })
                continue

            # Calculate BM25 score
            try:
                # Get scores for all documents for this keyword
                doc_scores = self.bm25_model.get_scores(keyword_tokens)

                # Get current document's score
                score = doc_scores[repo_index]

                # Ensure non-negative score
                score = max(0.0, score)

                keyword_scores.append({
                    "keyword": keyword,
                    "score": score,
                    "tokens": keyword_tokens
                })

            except Exception as e:
                logger.warning(f"Failed to calculate score for keyword '{keyword}': {e}")
                keyword_scores.append({
                    "keyword": keyword,
                    "score": 0.0,
                    "tokens": keyword_tokens
                })

        return keyword_scores

    def detect(self, url: str) -> DetectionResult:
        """Detect keyword stuffing in repository (based on BM25 algorithm)"""
        try:
            owner, repo_name = self.extract_repo_info(url)
            repo_full_name = f"{owner}/{repo_name}"

            # Get repository keywords
            keywords = self._get_repo_keywords(owner, repo_name)

            # Get README content
            readme_content = self._get_readme_content(owner, repo_name)

            if not keywords:
                return DetectionResult(
                    sub_category="keyword_stuffing",
                    url=url,
                    is_abuse=False,
                    confidence=0.0,
                    details={
                        "error": "No keywords found",
                        "keywords_found": 0,
                        "readme_found": bool(readme_content)
                    },
                    timestamp=datetime.now().isoformat()
                )

            # If no corpus exists, need to build one
            if not self.corpus_ready:
                # For simplicity, we'll use current repository as starting point
                if readme_content:
                    tokenized_doc = self._improved_tokenize(readme_content)
                    if tokenized_doc and len(tokenized_doc) > 10:
                        self.all_readmes = [tokenized_doc]
                        self.all_readme_repos = [repo_full_name]
                        self.bm25_model = self.BM25Okapi(self.all_readmes)
                        self.corpus_ready = True

            # Calculate BM25 scores
            keyword_scores = self._calculate_bm25_scores(repo_full_name, keywords, readme_content)

            if not keyword_scores:
                return DetectionResult(
                    sub_category="keyword_stuffing",
                    url=url,
                    is_abuse=False,
                    confidence=0.0,
                    details={
                        "error": "Failed to calculate keyword scores",
                        "total_keywords": len(keywords)
                    },
                    timestamp=datetime.now().isoformat()
                )

            # Count low-score keywords
            low_score_count = 0
            low_score_keywords = []

            for item in keyword_scores:
                if item["score"] < 2.0:  # New standard: score below 2.0
                    low_score_count += 1
                    low_score_keywords.append(item["keyword"])

            # Determine if abuse exists
            # New standard: more than 5 keywords with score below 2.0 is abuse
            is_abuse = low_score_count > 5

            # Calculate confidence (based on low-score keyword ratio)
            if len(keyword_scores) > 0:
                confidence = min(low_score_count / len(keyword_scores) * 1.5, 1.0)
            else:
                confidence = 0.0

            # Calculate average score
            avg_score = sum(item["score"] for item in keyword_scores) / len(keyword_scores) if keyword_scores else 0

            # Prepare detailed results
            sorted_scores = sorted(keyword_scores, key=lambda x: x["score"])

            details = {
                "total_keywords": len(keywords),
                "low_score_keywords_count": low_score_count,
                "low_score_keywords": low_score_keywords[:10],  # Show only top 10
                "avg_keyword_score": round(avg_score, 4),
                "threshold": ">5 keywords with BM25 score < 2.0",
                "readme_length": len(readme_content) if readme_content else 0,
                "corpus_size": len(self.all_readmes),
                "keyword_score_summary": {
                    "min_score": min(item["score"] for item in keyword_scores) if keyword_scores else 0,
                    "max_score": max(item["score"] for item in keyword_scores) if keyword_scores else 0,
                    "median_score": sorted_scores[len(sorted_scores) // 2]["score"] if sorted_scores else 0
                },
                "top_low_score_keywords": [
                    {"keyword": item["keyword"], "score": round(item["score"], 4)}
                    for item in sorted_scores[:5]  # Show 5 lowest scoring keywords
                ]
            }

            return DetectionResult(
                sub_category="keyword_stuffing",
                url=url,
                is_abuse=is_abuse,
                confidence=confidence,
                details=details,
                timestamp=datetime.now().isoformat()
            )

        except Exception as e:
            logger.error(f"Keyword stuffing detection failed: {e}")
            return DetectionResult(
                sub_category="keyword_stuffing",
                url=url,
                is_abuse=False,
                confidence=0.0,
                details={"error": str(e)},
                timestamp=datetime.now().isoformat()
            )


class AbuseDetectorFactory:
    """Detector factory"""

    def __init__(self, config_file: str = "config.json"):
        with open(config_file, 'r', encoding='utf-8') as f:
            self.config = json.load(f)

        self.detectors = {
            "fake_stars": FakeStarsDetector(self.config),
            "automatic_updates": AutomaticUpdatesDetector(self.config),
            "typo_squatting": TypoSquattingDetector(self.config),
            "reputation_farming": ReputationFarmingDetector(self.config),
            "fake_stats": FakeStatsDetector(self.config),
            "spoofed_contributor": SpoofedContributorDetector(self.config),
            "issue_spam": IssueSpamDetector(self.config),
            "keyword_stuffing": KeywordStuffingDetector(self.config)
        }

    def get_detector(self, sub_category: str) -> Optional[BaseDetector]:
        """Get detector by sub-category"""
        return self.detectors.get(sub_category)

    def detect_single(self, sub_category: str, url: str) -> DetectionResult:
        """Detect single entry"""
        detector = self.get_detector(sub_category)
        if not detector:
            return DetectionResult(
                sub_category=sub_category,
                url=url,
                is_abuse=False,
                confidence=0.0,
                details={"error": f"No detector for {sub_category}"},
                timestamp=datetime.now().isoformat()
            )

        return detector.detect(url)

    def detect_csv(self, csv_file: str, output_file: str = "detection_results.csv"):
        """Batch detection from CSV file"""
        results = []

        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                sub_category = row['sub_category']
                url = row['URL']

                if not url or not sub_category:
                    continue

                print(f"Detecting: {sub_category} - {url}")
                result = self.detect_single(sub_category, url)

                # Update CSV row
                row['detect_label'] = str(result.is_abuse)
                row['detect_details'] = json.dumps(result.details, ensure_ascii=False)

                results.append(row)

                # Avoid API rate limiting
                time.sleep(1)

        # Save results
        if results:
            fieldnames = list(results[0].keys())
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)

            print(f"Detection completed, results saved to: {output_file}")

        return results


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='GitHub Abuse Detection Framework')
    parser.add_argument('--csv', default="test_data/fake_stars_dataset_other.csv", help='Input CSV file path')
    parser.add_argument('--category', help='Detection category')
    parser.add_argument('--url', help='Detection URL')
    parser.add_argument('--output', default='test_data_results/fake_stars_results_small.csv', help='Output file path')

    args = parser.parse_args()

    factory = AbuseDetectorFactory()

    if args.csv:
        # Batch detection mode
        factory.detect_csv(args.csv, args.output)
    elif args.category and args.url:
        # Single detection mode
        result = factory.detect_single(args.category, args.url)
        print(f"Detection result: {result.is_abuse} (confidence: {result.confidence:.2f})")
        print(f"Details: {json.dumps(result.details, indent=2, ensure_ascii=False)}")
    else:
        print("Please provide CSV file or category and URL")


if __name__ == "__main__":
    main()