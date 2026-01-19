"""
GitHub Repository Name Squatting Detection Core Module
Time-segmented search strategy to bypass 1000 results limit
"""

import requests
import re
import time
import json
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from typing import Dict, List, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logger = logging.getLogger(__name__)


class TypoSquattingCoreDetector:
    def __init__(self, github_token: str = None, config: Dict = None):
        """
        Initialize core detector

        Args:
            github_token: GitHub personal access token
            config: Configuration dictionary
        """
        # Default configuration
        self.config = {
            "min_stars_low": 0,
            "max_stars_low": 10,
            "min_stars_high": 100,
            "similarity_threshold": 0.8,
            "min_fork_difference": 10,
            "search_per_page": 30,
            "similar_repo_check_count": 5,
            "exclude_topics": ["template", "boilerplate"],
            "max_retries": 3,
            "request_timeout": 30,
            "rate_limit_delay": 1.0,
            "time_segments": 12,
            "start_date": "2020-01-01",
            "end_date": "2024-12-31",
            "max_workers": 3,
            "segment_by": "month",
            "max_search_results": 1000,
            "max_repos_to_check": 100000
        }

        # Update with user configuration
        if config:
            self.config.update(config)

        self.github_token = github_token

        # Initialize session
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHub-TypoSquatting-Detector/1.0"
        })

        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"

        # API rate limit tracking
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = 0
        self.request_count = 0

    def make_api_call(self, url: str, params: Dict = None) -> Optional[Dict]:
        """Safe API call with rate limit handling"""
        self.request_count += 1
        max_retries = self.config.get("max_retries", 3)
        request_timeout = self.config.get("request_timeout", 30)
        rate_limit_delay = self.config.get("rate_limit_delay", 1.0)

        is_search_request = "search/repositories" in url

        for attempt in range(max_retries):
            try:
                response = self.session.get(url, params=params, timeout=request_timeout)

                # Check rate limits
                if 'X-RateLimit-Remaining' in response.headers:
                    self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
                    self.rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))

                    # Handle search API limits
                    if is_search_request and self.rate_limit_remaining < 5:
                        reset_time = self.rate_limit_reset
                        wait_time = max(reset_time - time.time(), 0)
                        if wait_time > 0:
                            logger.warning(f"[Search API] Rate limit approaching, waiting {wait_time:.0f} seconds...")
                            time.sleep(wait_time + 2)
                            continue

                    if self.rate_limit_remaining < 10:
                        wait_time = max(self.rate_limit_reset - time.time(), 0) + 10
                        logger.warning(f"[API Limit] {self.rate_limit_remaining} requests remaining, waiting {wait_time:.0f} seconds...")
                        time.sleep(wait_time)
                        continue

                if response.status_code == 200:
                    if is_search_request:
                        time.sleep(2)  # Extra delay between search requests
                    else:
                        time.sleep(rate_limit_delay)
                    return response.json()

                elif response.status_code == 403 and 'rate limit' in response.text.lower():
                    reset_time = response.headers.get('X-RateLimit-Reset')
                    if reset_time:
                        wait_time = max(int(reset_time) - time.time(), 0) + 10
                        logger.warning(f"[API Limit] Rate limit reached, waiting {wait_time:.0f} seconds...")
                        time.sleep(wait_time)
                        continue

                elif response.status_code in [404, 422]:
                    return None

                else:
                    logger.error(f"API call failed: {response.status_code} - {response.text[:100]}")
                    return None

            except requests.exceptions.RequestException as e:
                logger.error(f"Request exception: {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)

        return None

    def _generate_time_segments(self) -> List[Tuple[str, str]]:
        """Generate time segments"""
        segments = []

        start_date = datetime.strptime(self.config["start_date"], "%Y-%m-%d")
        end_date = datetime.strptime(self.config["end_date"], "%Y-%m-%d")
        segment_by = self.config.get("segment_by", "month")

        if segment_by == "month":
            # Segment by month
            current_date = start_date
            while current_date < end_date:
                segment_start = current_date.replace(day=1)

                if segment_start.month == 12:
                    next_month = segment_start.replace(year=segment_start.year + 1, month=1)
                else:
                    next_month = segment_start.replace(month=segment_start.month + 1)

                segment_end = min(next_month - timedelta(days=1), end_date)

                segments.append((
                    segment_start.strftime("%Y-%m-%d"),
                    segment_end.strftime("%Y-%m-%d")
                ))

                current_date = next_month

        elif segment_by == "quarter":
            # Segment by quarter
            current_date = start_date
            while current_date < end_date:
                quarter = (current_date.month - 1) // 3 + 1
                quarter_start_month = (quarter - 1) * 3 + 1

                segment_start = current_date.replace(month=quarter_start_month, day=1)

                next_quarter = quarter + 1
                if next_quarter > 4:
                    next_quarter = 1
                    next_quarter_year = segment_start.year + 1
                else:
                    next_quarter_year = segment_start.year

                next_quarter_start_month = (next_quarter - 1) * 3 + 1
                next_quarter_start = segment_start.replace(year=next_quarter_year, month=next_quarter_start_month)

                segment_end = min(next_quarter_start - timedelta(days=1), end_date)

                segments.append((
                    segment_start.strftime("%Y-%m-%d"),
                    segment_end.strftime("%Y-%m-%d")
                ))

                current_date = next_quarter_start

        else:  # year
            # Segment by year
            for year in range(start_date.year, end_date.year + 1):
                segment_start = max(start_date, datetime(year, 1, 1))
                segment_end = min(end_date, datetime(year, 12, 31))

                segments.append((
                    segment_start.strftime("%Y-%m-%d"),
                    segment_end.strftime("%Y-%m-%d")
                ))

        logger.info(f"Generated {len(segments)} time segments")
        return segments

    def _search_in_time_segment(self, segment: Tuple[str, str], base_query: str = "") -> List[Dict]:
        """Search repositories in specific time segment"""
        segment_start, segment_end = segment
        repos = []
        page = 1

        time_query = f"created:{segment_start}..{segment_end}"
        search_query = f"{base_query} {time_query}" if base_query else time_query

        logger.info(f"Searching time segment: {segment_start} to {segment_end}")

        while True:
            url = "https://api.github.com/search/repositories"
            params = {
                "q": search_query,
                "sort": "updated",
                "order": "desc",
                "per_page": min(self.config["search_per_page"], 100),
                "page": page
            }

            data = self.make_api_call(url, params)
            if not data or "items" not in data:
                break

            for item in data["items"]:
                # Exclude repositories with certain topics
                exclude_topics = self.config.get("exclude_topics", [])
                if any(topic in item.get("topics", []) for topic in exclude_topics):
                    continue

                repo_info = {
                    "full_name": item["full_name"],
                    "name": item["name"],
                    "owner": item["owner"]["login"],
                    "stars": item["stargazers_count"],
                    "forks": item["forks_count"],
                    "url": item["html_url"],
                    "description": item["description"] or "",
                    "created_at": item["created_at"],
                    "updated_at": item["updated_at"],
                    "time_segment": f"{segment_start}_{segment_end}"
                }
                repos.append(repo_info)

            if len(data["items"]) < params["per_page"]:
                break

            if len(repos) >= self.config["max_search_results"]:
                logger.warning(f"Time segment {segment_start} to {segment_end} reached maximum limit")
                break

            page += 1

        logger.info(f"Time segment {segment_start} to {segment_end} found {len(repos)} repositories")
        return repos

    def search_low_star_repos(self, repo_name: str = None) -> List[Dict]:
        """Search for low-star repositories with same name"""
        if repo_name:
            # If repository name specified, search for same-name low-star repositories
            query = f'"{repo_name}" in:name stars:{self.config["min_stars_low"]}..{self.config["max_stars_low"]} forks:<={self.config["min_fork_difference"]}'
        else:
            # Generic search: all low-star repositories
            query = f"stars:{self.config['min_stars_low']}..{self.config['max_stars_low']} forks:<={self.config['min_fork_difference']}"

        repos = []

        # Generate time segments
        time_segments = self._generate_time_segments()

        # Use thread pool for parallel searching
        max_workers = min(self.config.get("max_workers", 3), len(time_segments))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_segment = {
                executor.submit(self._search_in_time_segment, segment, query): segment
                for segment in time_segments
            }

            for future in as_completed(future_to_segment):
                segment = future_to_segment[future]
                try:
                    segment_repos = future.result()
                    repos.extend(segment_repos)

                    if len(repos) >= self.config["max_repos_to_check"]:
                        logger.info(f"Reached maximum repository check count: {self.config['max_repos_to_check']}")
                        for f in future_to_segment:
                            if not f.done():
                                f.cancel()
                        break

                except Exception as e:
                    logger.error(f"Time segment {segment} search failed: {e}")

        # Deduplicate
        seen = set()
        unique_repos = []
        for repo in repos:
            if repo["full_name"] not in seen:
                seen.add(repo["full_name"])
                unique_repos.append(repo)

        logger.info(f"Total found {len(unique_repos)} unique low-popularity repositories")
        return unique_repos

    def search_high_star_repos(self, repo_name: str, exclude_owner: str = None) -> List[Dict]:
        """Search for same-name high-star repositories"""
        url = "https://api.github.com/search/repositories"

        params = {
            "q": f'"{repo_name}" in:name stars:>={self.config["min_stars_high"]}',
            "sort": "stars",
            "order": "desc",
            "per_page": self.config.get("similar_repo_check_count", 5)
        }

        data = self.make_api_call(url, params)
        if not data or "items" not in data:
            return []

        high_star_repos = []
        for item in data["items"]:
            # Exclude self
            if exclude_owner and item["owner"]["login"] == exclude_owner:
                continue

            # Further filtering: names must be essentially same
            if item["name"].lower() != repo_name.lower():
                continue

            repo_info = {
                "full_name": item["full_name"],
                "name": item["name"],
                "owner": item["owner"]["login"],
                "stars": item["stargazers_count"],
                "forks": item["forks_count"],
                "url": item["html_url"],
                "description": item["description"] or "",
                "created_at": item["created_at"]
            }
            high_star_repos.append(repo_info)

        return high_star_repos

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts"""
        if not text1 or not text2:
            return 0.0

        text1_clean = re.sub(r'\s+', ' ', text1.strip().lower())
        text2_clean = re.sub(r'\s+', ' ', text2.strip().lower())

        return SequenceMatcher(None, text1_clean, text2_clean).ratio()

    def get_readme_content(self, owner: str, repo: str) -> Optional[str]:
        """Get repository's README content"""
        readme_files = ["README.md", "README.txt", "README", "README.MD"]

        for filename in readme_files:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
            data = self.make_api_call(url)

            if data and "content" in data:
                import base64
                try:
                    content = base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
                    return content
                except:
                    continue

        # If no standard README found, get repository description
        url = f"https://api.github.com/repos/{owner}/{repo}"
        data = self.make_api_call(url)

        if data and "description" in data:
            return data["description"] or ""

        return ""

    def detect_repository_abuse(self, repo_owner: str, repo_name: str) -> Tuple[bool, List[Dict], float]:
        """
        Detect typo squatting abuse for single repository

        Returns:
            Tuple[is_abuse, evidence_list, confidence]
        """
        try:
            # Get current repository information
            current_repo_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
            current_repo_data = self.make_api_call(current_repo_url)

            if not current_repo_data:
                return False, [], 0.0

            current_stars = current_repo_data.get('stargazers_count', 0)
            current_forks = current_repo_data.get('forks_count', 0)

            # If current repository already highly popular, unlikely to be abuse
            if current_stars >= self.config["min_stars_high"]:
                return False, [], 0.0

            # Search for same-name high-popularity repositories
            similar_repos = self.search_high_star_repos(repo_name, exclude_owner=repo_owner)

            if not similar_repos:
                return False, [], 0.0

            # Analyze similarity
            evidences = []
            highest_similarity = 0.0

            current_readme = self.get_readme_content(repo_owner, repo_name)

            for similar_repo in similar_repos:
                # Get high-popularity repository's README
                similar_readme = self.get_readme_content(similar_repo["owner"], similar_repo["name"])

                # Calculate similarity
                similarity = self._calculate_similarity(current_readme, similar_readme)
                highest_similarity = max(highest_similarity, similarity)

                # Check if abuse conditions met
                is_abuse = (
                        similarity >= self.config["similarity_threshold"] and
                        current_stars <= self.config["max_stars_low"] and
                        current_forks <= self.config["min_fork_difference"] and
                        similar_repo["stars"] >= self.config["min_stars_high"]
                )

                if is_abuse:
                    evidences.append({
                        "current_repo": f"{repo_owner}/{repo_name}",
                        "similar_repo": similar_repo["full_name"],
                        "similarity": similarity,
                        "current_stars": current_stars,
                        "current_forks": current_forks,
                        "similar_stars": similar_repo["stars"],
                        "similar_forks": similar_repo["forks"],
                        "description_similarity": similarity,
                        "abuse_reason": f"Too high similarity ({similarity:.1%}) with high-popularity repository {similar_repo['full_name']}"
                    })

            # Determine final result
            is_final_abuse = len(evidences) > 0

            # Confidence calculation
            if is_final_abuse:
                # Confidence based on highest similarity and evidence count
                confidence = min(highest_similarity * 0.8 + (len(evidences) * 0.1), 1.0)
            else:
                confidence = highest_similarity * 0.5

            return is_final_abuse, evidences, confidence

        except Exception as e:
            logger.error(f"Failed to detect repository {repo_owner}/{repo_name}: {e}")
            return False, [], 0.0

    def batch_detect_abuse(self, custom_query: str = None) -> List[Dict]:
        """
        Batch detect abuse (main function from original typo_squatting_detect.py)

        Returns:
            Detection results list
        """
        results = []

        # Search for low-star repositories
        low_star_repos = self.search_low_star_repos(custom_query)

        if not low_star_repos:
            logger.info("No qualifying low-popularity repositories found")
            return []

        logger.info(f"Starting analysis of {len(low_star_repos)} repositories...")

        for i, low_repo in enumerate(low_star_repos, 1):
            if i % 10 == 0:
                logger.info(f"Progress: {i}/{len(low_star_repos)} - analyzed {len(results)} repository pairs")

            # Search for same-name high-star repositories
            high_star_repos = self.search_high_star_repos(
                low_repo["name"],
                low_repo["owner"]
            )

            for high_repo in high_star_repos:
                # Get README contents
                low_readme = self.get_readme_content(low_repo["owner"], low_repo["name"])
                high_readme = self.get_readme_content(high_repo["owner"], high_repo["name"])

                # Calculate similarity
                similarity = self._calculate_similarity(low_readme, high_readme)

                # Check for abuse suspicion
                has_abuse_suspicion = (
                        similarity >= self.config["similarity_threshold"] and
                        high_repo["stars"] > low_repo["stars"] * 10 and
                        high_repo["forks"] > low_repo["forks"] * 5
                )

                result = {
                    "low_repo_url": low_repo["url"],
                    "low_repo_stars": low_repo["stars"],
                    "low_repo_forks": low_repo["forks"],
                    "high_repo_url": high_repo["url"],
                    "high_repo_stars": high_repo["stars"],
                    "high_repo_forks": high_repo["forks"],
                    "similarity": round(similarity, 3),
                    "has_abuse_suspicion": has_abuse_suspicion,
                    "low_repo_created": low_repo["created_at"],
                    "high_repo_created": high_repo["created_at"],
                    "star_ratio": round(high_repo["stars"] / max(low_repo["stars"], 1), 2),
                    "fork_ratio": round(high_repo["forks"] / max(low_repo["forks"], 1), 2),
                    "time_segment": low_repo.get("time_segment", "")
                }

                results.append(result)

                if has_abuse_suspicion:
                    logger.warning(
                        f"Possible abuse detected: {low_repo['url']} -> {high_repo['url']} (similarity: {similarity:.1%})")

        return results