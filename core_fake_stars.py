# core_fake_stars.py
"""
基于GitHub Archive的低活跃度用户打星检测核心模块
简化版：只使用SQL核心逻辑条件
"""

import time
import re
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import requests
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class LowActivityEvidence:
    """低活跃度证据"""
    actor: str
    actor_url: str
    first_active: str
    last_active: str
    n_actions: int
    n_repos: int
    n_orgs: int
    star_date: str
    matches_low_activity: bool


@dataclass
class AbuseEvidence:
    """滥用证据"""
    repo_full_name: str
    total_stars: int
    low_activity_stars: int
    low_activity_percentage: float
    low_activity_users: List[Dict[str, Any]]
    detection_reason: str
    meets_threshold: bool


class FakeStarsCoreDetector:
    """虚假星星核心检测器 - 简化版"""

    def __init__(self, github_token: str, config: Dict):
        """
        初始化检测器

        Args:
            github_token: GitHub API token
            config: 配置字典
        """
        self.github_token = github_token
        self.config = config

        # 初始化会话
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'GitHub-Abuse-Detector-FakeStars-SQL/1.0',
            'Authorization': f'token {github_token}'
        })

        # API设置
        self.api_settings = config.get('api_settings', {})
        self.max_retries = self.api_settings.get('max_retries', 3)
        self.request_timeout = self.api_settings.get('request_timeout', 30)
        self.rate_limit_delay = self.api_settings.get('rate_limit_delay', 1.5)

    def make_api_call(self, url: str, params: Dict = None) -> Optional[Dict]:
        """安全的API调用"""
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, params=params, timeout=self.request_timeout)

                # 处理速率限制
                if response.status_code == 403 and 'rate limit' in response.text.lower():
                    reset_time = response.headers.get('X-RateLimit-Reset', 0)
                    if reset_time:
                        wait_time = max(int(reset_time) - time.time(), 0) + 2
                        print(f"API限制，等待 {wait_time:.0f} 秒...")
                        time.sleep(wait_time)
                        continue

                if response.status_code == 200:
                    time.sleep(self.rate_limit_delay)
                    return response.json()
                elif response.status_code == 404:
                    return None
                else:
                    print(f"API调用失败: {response.status_code} - {response.text[:100]}")

            except requests.exceptions.RequestException as e:
                print(f"请求异常: {e}")
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)

        return None

    def extract_repo_info(self, repo_url: str) -> Tuple[str, str]:
        """从URL提取仓库信息"""
        repo_url = repo_url.rstrip('/').rstrip('.git')
        pattern = r"github\.com/([^/]+)/([^/?]+)"
        match = re.search(pattern, repo_url)
        if not match:
            raise ValueError(f"无效的GitHub仓库URL: {repo_url}")
        return match.group(1), match.group(2)

    def _get_user_activity_around_star(self, username: str, star_date: str, days_before_after: int = 60) -> Dict[
        str, Any]:
        """
        获取用户点赞事件前后指定天数内的活动信息

        Args:
            username: 用户名
            star_date: 点赞日期 (ISO格式)
            days_before_after: 检查前后多少天的活动

        Returns:
            用户活动信息字典
        """
        try:
            # 解析点赞日期
            star_dt = datetime.fromisoformat(star_date.replace('Z', '+00:00'))

            # 计算时间范围
            start_date = star_dt - timedelta(days=days_before_after)
            end_date = star_dt + timedelta(days=days_before_after)

            start_str = start_date.isoformat().replace('+00:00', 'Z')
            end_str = end_date.isoformat().replace('+00:00', 'Z')

            # 获取用户在该时间段内的公开事件
            events = []
            page = 1
            per_page = 100

            while True:
                events_url = f"https://api.github.com/users/{username}/events"
                params = {
                    'per_page': per_page,
                    'page': page
                }

                page_events = self.make_api_call(events_url, params)
                if not page_events:
                    break

                # 过滤时间范围内的活动
                for event in page_events:
                    event_date_str = event.get('created_at')
                    if event_date_str:
                        event_date = datetime.fromisoformat(event_date_str.replace('Z', '+00:00'))
                        if start_date <= event_date <= end_date:
                            events.append(event)

                # 如果已经获取到较早的时间点，停止
                if len(page_events) < per_page:
                    break

                # 检查是否已经获取到开始时间之前的数据
                last_event_date = page_events[-1].get('created_at')
                if last_event_date:
                    last_dt = datetime.fromisoformat(last_event_date.replace('Z', '+00:00'))
                    if last_dt < start_date:
                        break

                page += 1
                time.sleep(0.1)  # 避免API限制

            # 分析事件
            repo_set = set()
            org_set = set()
            event_dates = []

            for event in events:
                event_date = event.get('created_at')
                if event_date:
                    event_dates.append(event_date)

                # 记录涉及的仓库
                if 'repo' in event and event['repo']:
                    repo_name = event['repo'].get('name', '')
                    if repo_name:
                        repo_set.add(repo_name)

                # 记录涉及的组织（如果有）
                org = event.get('org')
                if org and org.get('login'):
                    org_set.add(org['login'])

            # 计算统计信息
            n_actions = len(events)
            n_repos = len(repo_set)
            n_orgs = len(org_set)

            # 确定首次和最后活跃时间
            if event_dates:
                first_active = min(event_dates)
                last_active = max(event_dates)
                same_day = first_active[:10] == last_active[:10]
            else:
                first_active = last_active = None
                same_day = False

            return {
                "username": username,
                "first_active": first_active,
                "last_active": last_active,
                "same_day_activity": same_day,
                "n_actions": n_actions,
                "n_repos": n_repos,
                "n_orgs": n_orgs,
                "analysis_period_days": days_before_after * 2,  # 总分析天数
                "star_date": star_date,
                "events_in_period": n_actions
            }

        except Exception as e:
            print(f"获取用户活动信息失败 {username}: {e}")
            return {
                "username": username,
                "error": str(e),
                "first_active": None,
                "last_active": None,
                "same_day_activity": False,
                "n_actions": 0,
                "n_repos": 0,
                "n_orgs": 0
            }

    def _is_low_activity_user(self, user_activity: Dict) -> bool:
        """
        判断用户是否为低活跃度用户（基于SQL逻辑）
        简化版：只检查4个核心条件

        Args:
            user_activity: 用户活动信息

        Returns:
            是否为低活跃度用户
        """
        if "error" in user_activity:
            return False

        # 4个核心条件：
        # 1. first_active = last_active (同一天活跃)
        # 2. n_actions <= 2
        # 3. n_repos <= 1
        # 4. n_orgs <= 1

        conditions = [
            user_activity.get("same_day_activity", False),
            user_activity.get("n_actions", 0) <= self.config.get('max_actions', 2),
            user_activity.get("n_repos", 0) <= self.config.get('max_repos', 1),
            user_activity.get("n_orgs", 0) <= self.config.get('max_orgs', 1),
        ]

        # 必须同时满足所有4个条件
        return all(conditions)

    def _get_stargazers_with_details(self, owner: str, repo_name: str) -> List[Dict]:
        """获取stargazers及其活动信息 - 并行优化版"""
        stargazers = []
        page = 1
        per_page = self.config.get('stargazers_per_page', 100)
        max_stargazers = self.config.get('max_stargazers_to_check', 300)
        days_before_after = self.config.get('activity_days_around_star', 60)

        print(f"开始获取仓库 {owner}/{repo_name} 的stargazers...")

        # 第一步：批量获取所有stargazer基本信息
        all_stargazer_basics = []
        while len(all_stargazer_basics) < max_stargazers:
            url = f"https://api.github.com/repos/{owner}/{repo_name}/stargazers"
            params = {'page': page, 'per_page': per_page}

            response = self.session.get(
                url,
                params=params,
                headers={
                    **self.session.headers,
                    "Accept": "application/vnd.github.v3.star+json"
                },
                timeout=self.request_timeout
            )

            if response.status_code == 200:
                data = response.json()
                time.sleep(self.rate_limit_delay)
            else:
                break

            if not data:
                break

            all_stargazer_basics.extend(data)

            if len(data) < per_page:
                break

            page += 1
            time.sleep(0.5)  # 分页延迟

        # 限制数量
        all_stargazer_basics = all_stargazer_basics[:max_stargazers]
        print(f"获取到 {len(all_stargazer_basics)} 个stargazer基本信息")

        # 第二步：并行处理用户活动信息
        def process_stargazer(star):
            username = star.get('login') or star.get('user', {}).get('login')
            if not username:
                return None

            # 关键修复：获取正确的点赞时间
            star_date = star.get('starred_at')

            # 获取用户点赞前后60天的活动信息
            user_activity = self._get_user_activity_around_star(
                username,
                star_date,
                days_before_after
            )

            return {
                "username": username,
                "user_url": f"https://github.com/{username}",
                "starred_at": star_date,
                "user_activity": user_activity,
                "is_low_activity": self._is_low_activity_user(user_activity)
            }

        # 使用线程池并行处理
        max_workers = min(self.config.get('max_workers', 8), 20)  # 控制并发数，避免API限制
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_star = {
                executor.submit(process_stargazer, star): star
                for star in all_stargazer_basics
            }

            # 收集结果
            completed_count = 0
            for future in as_completed(future_to_star):
                try:
                    result = future.result(timeout=60)
                    if result:
                        stargazers.append(result)
                        completed_count += 1

                        # 进度显示
                        if completed_count % 10 == 0:
                            print(f"已处理 {completed_count}/{len(all_stargazer_basics)} 个用户...")

                except Exception as e:
                    print(f"处理stargazer失败: {e}")
                    continue

        print(f"获取完成，共 {len(stargazers)} 个stargazers详细信息")
        return stargazers

    def detect_repository_abuse(self, owner: str, repo_name: str) -> Tuple[bool, List[AbuseEvidence], float]:
        """
        检测仓库是否存在虚假星星滥用

        Args:
            owner: 仓库所有者
            repo_name: 仓库名

        Returns:
            (is_abuse, evidences, confidence)
        """
        try:
            repo_full_name = f"{owner}/{repo_name}"

            # 获取仓库基本信息
            repo_info = self.make_api_call(f"https://api.github.com/repos/{owner}/{repo_name}")
            if not repo_info:
                return False, [], 0.0

            total_stars = repo_info.get('stargazers_count', 0)
            print(f"仓库 {repo_full_name} 共有 {total_stars} 个stars")

            # 如果星星数太少，不需要检测
            if total_stars < self.config.get('min_stars_for_detection', 30):
                return False, [], 0.0

            # 获取stargazers详细信息
            stargazers = self._get_stargazers_with_details(owner, repo_name)

            if not stargazers:
                return False, [], 0.0

            # 统计低活跃度用户
            low_activity_users = []
            for star in stargazers:
                if star.get('is_low_activity', False):
                    low_activity_users.append(star)

            # 计算比例
            low_activity_count = len(low_activity_users)
            low_activity_percentage = low_activity_count / len(stargazers)

            print(f"低活跃度用户: {low_activity_count}/{len(stargazers)} ({low_activity_percentage:.2%})")

            # 判断是否滥用
            min_low_activity_stars1 = self.config.get('min_low_activity_stars1', 100)
            min_low_activity_stars2 = self.config.get('min_low_activity_stars2', 20)
            min_low_activity_percentage = self.config.get('min_low_activity_percentage', 0.1)

            meets_count_threshold1 = low_activity_count >= min_low_activity_stars1
            meets_count_threshold2 = low_activity_count >= min_low_activity_stars2
            meets_percentage_threshold = low_activity_percentage >= min_low_activity_percentage

            is_abuse = meets_count_threshold1 or (meets_percentage_threshold and meets_count_threshold2)

            # 计算置信度
            confidence = 0.0
            if is_abuse:
                # 基于低活跃度比例计算置信度
                base_confidence = min(low_activity_percentage * 1.5, 1.0)

                # 如果比例很高，增加置信度
                if low_activity_percentage > 0.3:
                    confidence = min(base_confidence * 1.2, 1.0)
                elif low_activity_percentage > 0.5:
                    confidence = min(base_confidence * 1.5, 1.0)
                else:
                    confidence = base_confidence

            # 准备证据
            evidence = AbuseEvidence(
                repo_full_name=repo_full_name,
                total_stars=total_stars,
                low_activity_stars=low_activity_count,
                low_activity_percentage=low_activity_percentage,
                low_activity_users=[
                    {
                        "username": user["username"],
                        "user_url": user["user_url"],
                        "starred_at": user["starred_at"],
                        "n_actions": user["user_activity"].get("n_actions", 0),
                        "n_repos": user["user_activity"].get("n_repos", 0),
                        "n_orgs": user["user_activity"].get("n_orgs", 0),
                        "same_day_activity": user["user_activity"].get("same_day_activity", False),
                        "analysis_period_days": user["user_activity"].get("analysis_period_days", 120)
                    }
                    for user in low_activity_users[:10]  # 只显示前10个
                ],
                detection_reason=f"发现 {low_activity_count} 个低活跃度用户打星 ({low_activity_percentage:.1%})",
                meets_threshold=is_abuse
            )

            return is_abuse, [evidence], confidence

        except Exception as e:
            print(f"检测仓库滥用失败 {owner}/{repo_name}: {e}")
            return False, [], 0.0