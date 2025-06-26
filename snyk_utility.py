    elif args.command == 'add-waivers-template':
        utility.add_waivers_from_template(args.project_ids_file, args.template, args.days)
    
    elif args.command == 'add-waiver-cross-projects':
        utility.add_waivers_by_issue_across_projects(
            args.project_ids_file,
            args.issue_reference,
            args.description,
            args.type,
            args.days
        )
    
    elif args.command == 'retest-projects':
        utility.trigger_project_retests(args.project_ids_file, args.projects)
    
    elif args.command == 'test-status':
        utility.check_project_test_status(args.project_ids_file)
    
    elif args.command == 'retest-with-issues':
        utility.retest_projects_with_issues(args.project_ids_file, args.severity)
    
    elif args.command == 'add-waiver-cross-projects':
        utility.add_waivers_by_issue_across_projects(
            args.project_ids_file,
            args.issue_reference,
            args.description,
            args.type,
            args.days
        )#!/usr/bin/env python3
"""
Snyk REST API Utility

A comprehensive utility for interacting with Snyk's REST API to:
1. Check for distinct issues across multiple projects
2. Add waivers for issues with customizable parameters

Usage:
    python snyk_utility.py --help
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
import requests
from dataclasses import dataclass
import time


@dataclass
class WaiverTemplate:
    """Represents a waiver template for common scenarios"""
    name: str
    description: str
    waiver_type: str
    default_days: int
    justification: str
    category: str
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'description': self.description,
            'waiver_type': self.waiver_type,
            'default_days': self.default_days,
            'justification': self.justification,
            'category': self.category
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'WaiverTemplate':
        return cls(
            name=data['name'],
            description=data['description'],
            waiver_type=data['waiver_type'],
            default_days=data['default_days'],
            justification=data['justification'],
            category=data['category']
        )


class WaiverTemplateManager:
    """Manages waiver templates"""
    
    def __init__(self, templates_file: str = 'waiver_templates.json'):
        self.templates_file = templates_file
        self.templates = self._load_default_templates()
        self._load_custom_templates()
    
    def _load_default_templates(self) -> List[WaiverTemplate]:
        """Load built-in waiver templates"""
        return [
            WaiverTemplate(
                name="false_positive",
                description="False Positive - Issue not applicable to our use case",
                waiver_type="not-applicable",
                default_days=365,
                justification="After analysis, this vulnerability does not apply to our specific implementation or usage pattern.",
                category="analysis"
            ),
            WaiverTemplate(
                name="dev_dependency",
                description="Development Dependency - Not in production",
                waiver_type="not-applicable",
                default_days=180,
                justification="This vulnerability exists in a development-only dependency and does not affect production code.",
                category="environment"
            ),
            WaiverTemplate(
                name="upgrade_planned",
                description="Upgrade Planned - Fix scheduled",
                waiver_type="temporary",
                default_days=90,
                justification="Upgrade to resolve this vulnerability is planned and scheduled for the next release cycle.",
                category="remediation"
            ),
            WaiverTemplate(
                name="no_exploit_path",
                description="No Exploit Path - Code path not accessible",
                waiver_type="not-applicable",
                default_days=365,
                justification="The vulnerable code path is not accessible in our application architecture.",
                category="analysis"
            ),
            WaiverTemplate(
                name="low_risk_accepted",
                description="Low Risk Accepted - Business decision to accept",
                waiver_type="wont-fix",
                default_days=365,
                justification="After risk assessment, business has decided to accept this low-risk vulnerability.",
                category="business"
            ),
            WaiverTemplate(
                name="legacy_system",
                description="Legacy System - Cannot be updated",
                waiver_type="wont-fix",
                default_days=730,
                justification="This is a legacy system that cannot be updated due to business constraints.",
                category="legacy"
            ),
            WaiverTemplate(
                name="vendor_patch_pending",
                description="Vendor Patch Pending - Waiting for upstream fix",
                waiver_type="temporary",
                default_days=180,
                justification="Waiting for vendor to release a patch for this vulnerability.",
                category="vendor"
            ),
            WaiverTemplate(
                name="test_environment",
                description="Test Environment - Not production critical",
                waiver_type="not-applicable",
                default_days=180,
                justification="This vulnerability exists in test environment and does not impact production security.",
                category="environment"
            ),
            WaiverTemplate(
                name="internal_tool",
                description="Internal Tool - Limited exposure",
                waiver_type="wont-fix",
                default_days=365,
                justification="This is an internal tool with limited exposure and accepted risk.",
                category="business"
            )
        ]
    
    def _load_custom_templates(self):
        """Load custom templates from file"""
        if Path(self.templates_file).exists():
            try:
                with open(self.templates_file, 'r') as f:
                    data = json.load(f)
                    custom_templates = [WaiverTemplate.from_dict(t) for t in data.get('custom_templates', [])]
                    self.templates.extend(custom_templates)
            except Exception as e:
                print(f"Warning: Could not load custom templates: {e}")
    
    def save_custom_templates(self):
        """Save custom templates to file"""
        # Only save templates that aren't in the default set
        default_names = {t.name for t in self._load_default_templates()}
        custom_templates = [t for t in self.templates if t.name not in default_names]
        
        data = {
            'custom_templates': [t.to_dict() for t in custom_templates],
            'last_updated': datetime.now().isoformat()
        }
        
        with open(self.templates_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def list_templates(self, category: Optional[str] = None) -> List[WaiverTemplate]:
        """List all templates, optionally filtered by category"""
        if category:
            return [t for t in self.templates if t.category == category]
        return self.templates
    
    def get_template(self, name: str) -> Optional[WaiverTemplate]:
        """Get a specific template by name"""
        for template in self.templates:
            if template.name == name:
                return template
        return None
    
    def add_template(self, template: WaiverTemplate) -> bool:
        """Add a new custom template"""
        # Check if template already exists
        if self.get_template(template.name):
            return False
        
        self.templates.append(template)
        self.save_custom_templates()
        return True
    
    def remove_template(self, name: str) -> bool:
        """Remove a custom template"""
        # Don't allow removal of default templates
        default_names = {t.name for t in self._load_default_templates()}
        if name in default_names:
            return False
        
        for i, template in enumerate(self.templates):
            if template.name == name:
                del self.templates[i]
                self.save_custom_templates()
                return True
        return False
    
    def get_categories(self) -> List[str]:
        """Get all available categories"""
        return list(set(t.category for t in self.templates))


@dataclass
class SnykIssue:
    """Represents a Snyk security issue"""
    id: str
    title: str
    severity: str
    issue_type: str
    project_id: str
    project_name: str
    package_name: str
    package_version: str
    introduced_date: str
    
    def __hash__(self):
        # Use issue ID and package info for uniqueness
        return hash((self.id, self.package_name, self.package_version))
    
    def __eq__(self, other):
        if not isinstance(other, SnykIssue):
            return False
        return (self.id == other.id and 
                self.package_name == other.package_name and 
                self.package_version == other.package_version)


@dataclass
class SnykWaiver:
    """Represents a Snyk issue waiver"""
    id: str
    issue_id: str
    project_id: str
    project_name: str
    reason: str
    waiver_type: str
    created_date: str
    expiry_date: str
    created_by: str
    is_active: bool
    issue_title: str
    issue_severity: str


class SnykAPIClient:
    """Client for interacting with Snyk REST API"""
    
    def __init__(self, api_token: str, org_id: str, base_url: str = "https://api.snyk.io"):
        self.api_token = api_token
        self.org_id = org_id
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {api_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('snyk_utility.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make an API request with error handling and rate limiting"""
        url = f"{self.base_url}{endpoint}"
        
        max_retries = 3
        backoff_factor = 1
        
        for attempt in range(max_retries):
            try:
                response = self.session.request(method, url, **kwargs)
                
                if response.status_code == 429:  # Rate limited
                    retry_after = int(response.headers.get('Retry-After', 60))
                    self.logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    self.logger.error(f"Request failed after {max_retries} attempts: {e}")
                    raise
                
                wait_time = backoff_factor * (2 ** attempt)
                self.logger.warning(f"Request failed, retrying in {wait_time} seconds...")
                time.sleep(wait_time)
        
        raise Exception("Max retries exceeded")
    
    def get_project_issues(self, project_id: str) -> List[SnykIssue]:
        """Get all issues for a specific project"""
        self.logger.info(f"Fetching issues for project {project_id}")
        
        try:
            # Get project details first
            project_response = self._make_request(
                'GET', 
                f'/rest/orgs/{self.org_id}/projects/{project_id}'
            )
            project_data = project_response.json()
            project_name = project_data.get('data', {}).get('attributes', {}).get('name', 'Unknown')
            
            # Get issues for the project
            issues_response = self._make_request(
                'GET',
                f'/rest/orgs/{self.org_id}/issues',
                params={
                    'project_id': project_id,
                    'limit': 1000  # Adjust as needed
                }
            )
            
            issues_data = issues_response.json()
            issues = []
            
            for issue_data in issues_data.get('data', []):
                attrs = issue_data.get('attributes', {})
                relationships = issue_data.get('relationships', {})
                
                # Extract package information
                package_name = 'Unknown'
                package_version = 'Unknown'
                
                if 'problems' in relationships:
                    problems = relationships['problems'].get('data', [])
                    if problems:
                        # Get the first problem's details
                        problem_id = problems[0]['id']
                        # You might need to make additional calls to get package details
                        # This is simplified for the example
                
                issue = SnykIssue(
                    id=issue_data['id'],
                    title=attrs.get('title', 'Unknown'),
                    severity=attrs.get('severity', 'unknown'),
                    issue_type=attrs.get('type', 'unknown'),
                    project_id=project_id,
                    project_name=project_name,
                    package_name=package_name,
                    package_version=package_version,
                    introduced_date=attrs.get('created_at', 'unknown')
                )
                issues.append(issue)
            
            self.logger.info(f"Found {len(issues)} issues in project {project_id}")
            return issues
            
        except Exception as e:
            self.logger.error(f"Failed to get issues for project {project_id}: {e}")
            return []
    
    def get_distinct_issues(self, project_ids: List[str]) -> Set[SnykIssue]:
        """Get distinct issues across multiple projects"""
        self.logger.info(f"Checking distinct issues across {len(project_ids)} projects")
        
        all_issues = set()
        
        for project_id in project_ids:
            project_issues = self.get_project_issues(project_id)
            all_issues.update(project_issues)
        
        self.logger.info(f"Found {len(all_issues)} distinct issues across all projects")
        return all_issues
    
    def add_waiver(self, issue_id: str, project_id: str, waiver_description: str, 
                   waiver_type: str, days: int) -> bool:
        """Add a waiver for a specific issue"""
        self.logger.info(f"Adding waiver for issue {issue_id} in project {project_id}")
        
        # Calculate expiry date
        expiry_date = datetime.now() + timedelta(days=days)
        
        waiver_data = {
            'data': {
                'type': 'issue_waiver',
                'attributes': {
                    'reason': waiver_description,
                    'waiver_type': waiver_type,
                    'expiry': expiry_date.isoformat(),
                    'justification': waiver_description
                },
                'relationships': {
                    'issue': {
                        'data': {
                            'type': 'issue',
                            'id': issue_id
                        }
                    }
                }
            }
        }
        
        try:
            response = self._make_request(
                'POST',
                f'/rest/orgs/{self.org_id}/projects/{project_id}/issues/{issue_id}/waivers',
                json=waiver_data
            )
            
            self.logger.info(f"Successfully added waiver for issue {issue_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add waiver for issue {issue_id}: {e}")
            return False
    
    def get_existing_waivers_for_issue(self, issue_id: str, project_id: str) -> List[SnykWaiver]:
        """Get existing waivers for a specific issue in a project"""
        try:
            waivers_response = self._make_request(
                'GET',
                f'/rest/orgs/{self.org_id}/projects/{project_id}/issues/{issue_id}/waivers'
            )
            
            waivers_data = waivers_response.json()
            waivers = []
            
            for waiver_data in waivers_data.get('data', []):
                attrs = waiver_data.get('attributes', {})
                
                # Check if waiver is active
                expiry_str = attrs.get('expiry', '')
                is_active = True
                if expiry_str:
                    try:
                        expiry_date = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                        is_active = expiry_date > datetime.now(expiry_date.tzinfo)
                    except:
                        pass
                
                waiver = SnykWaiver(
                    id=waiver_data['id'],
                    issue_id=issue_id,
                    project_id=project_id,
                    project_name='',  # Not needed for this check
                    reason=attrs.get('reason', ''),
                    waiver_type=attrs.get('waiver_type', ''),
                    created_date=attrs.get('created', ''),
                    expiry_date=attrs.get('expiry', ''),
                    created_by=attrs.get('created_by', ''),
                    is_active=is_active,
                    issue_title='',  # Not needed for this check
                    issue_severity=''  # Not needed for this check
                )
                waivers.append(waiver)
            
            return waivers
            
        except Exception as e:
            self.logger.error(f"Failed to get existing waivers for issue {issue_id}: {e}")
            return []
    
    def smart_add_waiver(self, issue_id: str, project_id: str, waiver_description: str, 
                        waiver_type: str, days: int, skip_if_waived: bool = True) -> Dict[str, str]:
        """
        Intelligently add a waiver, checking for existing waivers and issue existence
        Returns dict with status: 'added', 'skipped_existing_waiver', 'skipped_no_issue', 'failed'
        """
        self.logger.debug(f"Smart waiver check for issue {issue_id} in project {project_id}")
        
        # First, check if the issue exists in this project
        try:
            issue_response = self._make_request(
                'GET',
                f'/rest/orgs/{self.org_id}/projects/{project_id}/issues/{issue_id}'
            )
            # If we get here, the issue exists
        except Exception as e:
            self.logger.debug(f"Issue {issue_id} not found in project {project_id}: {e}")
            return {'status': 'skipped_no_issue', 'reason': 'Issue not found in this project'}
        
        # Check for existing active waivers if requested
        if skip_if_waived:
            existing_waivers = self.get_existing_waivers_for_issue(issue_id, project_id)
            active_waivers = [w for w in existing_waivers if w.is_active]
            
            if active_waivers:
                self.logger.debug(f"Active waiver already exists for issue {issue_id} in project {project_id}")
                return {
                    'status': 'skipped_existing_waiver', 
                    'reason': f'Active waiver already exists (expires: {active_waivers[0].expiry_date})'
                }
        
        # Add the waiver
        success = self.add_waiver(issue_id, project_id, waiver_description, waiver_type, days)
        
        if success:
            return {'status': 'added', 'reason': 'Waiver added successfully'}
        else:
            return {'status': 'failed', 'reason': 'Failed to add waiver'}
    
    def bulk_add_waivers(self, issues: List[SnykIssue], waiver_description: str,
                        waiver_type: str, days: int, skip_if_waived: bool = True) -> Dict[str, Dict[str, str]]:
        """Add waivers for multiple issues with intelligent checking"""
        self.logger.info(f"Adding waivers for {len(issues)} issues (skip_if_waived={skip_if_waived})")
        
        results = {}
        
        for issue in issues:
            result = self.smart_add_waiver(
                issue.id, 
                issue.project_id, 
                waiver_description, 
                waiver_type, 
                days,
                skip_if_waived
            )
            results[f"{issue.id}:{issue.project_id}"] = result
        
        # Count results
        added = sum(1 for r in results.values() if r['status'] == 'added')
        skipped_waived = sum(1 for r in results.values() if r['status'] == 'skipped_existing_waiver')
        skipped_no_issue = sum(1 for r in results.values() if r['status'] == 'skipped_no_issue')
        failed = sum(1 for r in results.values() if r['status'] == 'failed')
        
        self.logger.info(f"Waiver results - Added: {added}, Skipped (existing waiver): {skipped_waived}, "
                        f"Skipped (no issue): {skipped_no_issue}, Failed: {failed}")
        
        return results
    
    def bulk_add_waivers_by_project_list(self, project_ids: List[str], issue_reference: str,
                                       waiver_description: str, waiver_type: str, days: int,
                                       skip_if_waived: bool = True) -> Dict[str, Dict[str, str]]:
        """
        Add waivers for a specific issue across multiple projects
        Only adds waiver if:
        1. The issue exists in the project
        2. There isn't already an active waiver (if skip_if_waived=True)
        """
        self.logger.info(f"Adding waivers for issue '{issue_reference}' across {len(project_ids)} projects")
        
        results = {}
        
        for project_id in project_ids:
            # For issue reference, we need to find the actual issue ID in this project
            # This could be an exact issue ID or we need to search by title
            
            try:
                # Try direct issue ID first
                if issue_reference.startswith('SNYK-'):
                    issue_id = issue_reference
                else:
                    # Search for issues by title pattern in this project
                    project_issues = self.get_project_issues(project_id)
                    matching_issues = [
                        issue for issue in project_issues 
                        if issue_reference.lower() in issue.title.lower()
                    ]
                    
                    if not matching_issues:
                        results[project_id] = {
                            'status': 'skipped_no_issue',
                            'reason': f'No issues matching "{issue_reference}" found in project'
                        }
                        continue
                    elif len(matching_issues) > 1:
                        results[project_id] = {
                            'status': 'failed',
                            'reason': f'Multiple issues matching "{issue_reference}" found - be more specific'
                        }
                        continue
                    else:
                        issue_id = matching_issues[0].id
                
                # Now add waiver for this specific issue in this project
                result = self.smart_add_waiver(
                    issue_id,
                    project_id,
                    waiver_description,
                    waiver_type,
                    days,
                    skip_if_waived
                )
                results[project_id] = result
                
            except Exception as e:
                self.logger.error(f"Error processing project {project_id}: {e}")
                results[project_id] = {
                    'status': 'failed',
                    'reason': f'Error processing project: {str(e)}'
                }
        
        # Log summary
        added = sum(1 for r in results.values() if r['status'] == 'added')
        skipped_waived = sum(1 for r in results.values() if r['status'] == 'skipped_existing_waiver')
        skipped_no_issue = sum(1 for r in results.values() if r['status'] == 'skipped_no_issue')
        failed = sum(1 for r in results.values() if r['status'] == 'failed')
        
        self.logger.info(f"Project waiver results - Added: {added}, Skipped (existing waiver): {skipped_waived}, "
                        f"Skipped (no issue): {skipped_no_issue}, Failed: {failed}")
        
        return results
    
    def get_all_waivers(self, project_ids: List[str], active_only: bool = True) -> List[SnykWaiver]:
        """Get all waivers across multiple projects"""
        self.logger.info(f"Fetching waivers from {len(project_ids)} projects (active_only={active_only})")
        
        all_waivers = []
        
        for project_id in project_ids:
            try:
                # Get project details
                project_response = self._make_request(
                    'GET', 
                    f'/rest/orgs/{self.org_id}/projects/{project_id}'
                )
                project_data = project_response.json()
                project_name = project_data.get('data', {}).get('attributes', {}).get('name', 'Unknown')
                
                # Get waivers for the project
                waivers_response = self._make_request(
                    'GET',
                    f'/rest/orgs/{self.org_id}/projects/{project_id}/waivers',
                    params={'limit': 1000}
                )
                
                waivers_data = waivers_response.json()
                
                for waiver_data in waivers_data.get('data', []):
                    attrs = waiver_data.get('attributes', {})
                    relationships = waiver_data.get('relationships', {})
                    
                    # Get issue information
                    issue_id = None
                    issue_title = 'Unknown'
                    issue_severity = 'unknown'
                    
                    if 'issue' in relationships:
                        issue_data = relationships['issue'].get('data', {})
                        issue_id = issue_data.get('id')
                        
                        # Fetch issue details if needed
                        if issue_id:
                            try:
                                issue_response = self._make_request(
                                    'GET',
                                    f'/rest/orgs/{self.org_id}/issues/{issue_id}'
                                )
                                issue_info = issue_response.json()
                                issue_attrs = issue_info.get('data', {}).get('attributes', {})
                                issue_title = issue_attrs.get('title', 'Unknown')
                                issue_severity = issue_attrs.get('severity', 'unknown')
                            except:
                                pass  # Continue with unknown issue details
                    
                    # Check if waiver is active
                    expiry_str = attrs.get('expiry', '')
                    is_active = True
                    if expiry_str:
                        try:
                            expiry_date = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                            is_active = expiry_date > datetime.now(expiry_date.tzinfo)
                        except:
                            pass
                    
                    # Skip inactive waivers if only active ones requested
                    if active_only and not is_active:
                        continue
                    
                    waiver = SnykWaiver(
                        id=waiver_data['id'],
                        issue_id=issue_id or 'Unknown',
                        project_id=project_id,
                        project_name=project_name,
                        reason=attrs.get('reason', 'No reason provided'),
                        waiver_type=attrs.get('waiver_type', 'unknown'),
                        created_date=attrs.get('created', 'unknown'),
                        expiry_date=attrs.get('expiry', 'unknown'),
                        created_by=attrs.get('created_by', 'unknown'),
                        is_active=is_active,
                        issue_title=issue_title,
                        issue_severity=issue_severity
                    )
                    all_waivers.append(waiver)
                
                self.logger.info(f"Found {len([w for w in all_waivers if w.project_id == project_id])} waivers in project {project_id}")
                
            except Exception as e:
                self.logger.error(f"Failed to get waivers for project {project_id}: {e}")
                continue
        
        self.logger.info(f"Found {len(all_waivers)} total waivers")
        return all_waivers
    
    def remove_waiver(self, waiver_id: str, project_id: str) -> bool:
        """Remove a specific waiver"""
        self.logger.info(f"Removing waiver {waiver_id} from project {project_id}")
        
        try:
            response = self._make_request(
                'DELETE',
                f'/rest/orgs/{self.org_id}/projects/{project_id}/waivers/{waiver_id}'
            )
            
            self.logger.info(f"Successfully removed waiver {waiver_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to remove waiver {waiver_id}: {e}")
            return False
    
    def bulk_remove_waivers_by_issue(self, issue_reference: str, project_ids: List[str]) -> Dict[str, bool]:
        """Remove all waivers for issues matching the reference (issue ID or title pattern)"""
        self.logger.info(f"Removing waivers for issue reference: {issue_reference}")
        
        # Get all waivers
        all_waivers = self.get_all_waivers(project_ids, active_only=False)
        
        # Find matching waivers
        matching_waivers = []
        for waiver in all_waivers:
            if (issue_reference == waiver.issue_id or 
                issue_reference.lower() in waiver.issue_title.lower()):
                matching_waivers.append(waiver)
        
        if not matching_waivers:
            self.logger.warning(f"No waivers found matching reference: {issue_reference}")
            return {}
        
        self.logger.info(f"Found {len(matching_waivers)} waivers to remove")
        
        # Remove waivers
        results = {}
        for waiver in matching_waivers:
            success = self.remove_waiver(waiver.id, waiver.project_id)
            results[waiver.id] = success
        
        successful = sum(1 for success in results.values() if success)
        self.logger.info(f"Successfully removed {successful}/{len(matching_waivers)} waivers")
        
        return results
    
    def get_waiver_statistics(self, project_ids: List[str]) -> Dict:
        """Get comprehensive waiver statistics"""
        self.logger.info("Generating waiver statistics")
        
        all_waivers = self.get_all_waivers(project_ids, active_only=False)
        active_waivers = [w for w in all_waivers if w.is_active]
        expired_waivers = [w for w in all_waivers if not w.is_active]
        
        # Count by type
        type_counts = {}
        for waiver in all_waivers:
            type_counts[waiver.waiver_type] = type_counts.get(waiver.waiver_type, 0) + 1
        
        # Count by severity
        severity_counts = {}
        for waiver in all_waivers:
            severity_counts[waiver.issue_severity] = severity_counts.get(waiver.issue_severity, 0) + 1
        
        # Count by project
        project_counts = {}
        for waiver in all_waivers:
            project_counts[waiver.project_name] = project_counts.get(waiver.project_name, 0) + 1
        
        # Expiring soon (next 30 days)
        expiring_soon = []
        cutoff_date = datetime.now() + timedelta(days=30)
        
        for waiver in active_waivers:
            if waiver.expiry_date != 'unknown':
                try:
                    expiry_date = datetime.fromisoformat(waiver.expiry_date.replace('Z', '+00:00'))
                    if expiry_date <= cutoff_date:
                        expiring_soon.append(waiver)
                except:
                    pass
        
        return {
            'total_waivers': len(all_waivers),
            'active_waivers': len(active_waivers),
            'expired_waivers': len(expired_waivers),
            'expiring_soon': len(expiring_soon),
            'by_type': type_counts,
            'by_severity': severity_counts,
            'by_project': project_counts,
            'expiring_soon_details': [
                {
                    'waiver_id': w.id,
                    'issue_title': w.issue_title,
                    'project_name': w.project_name,
                    'expiry_date': w.expiry_date
                } for w in expiring_soon
            ]
        }
    
    def find_duplicate_waivers(self, project_ids: List[str]) -> List[List[SnykWaiver]]:
        """Find duplicate waivers (same issue across different projects or multiple waivers for same issue)"""
        self.logger.info("Finding duplicate waivers")
        
        all_waivers = self.get_all_waivers(project_ids, active_only=True)
        
        # Group by issue_id
        issue_groups = {}
        for waiver in all_waivers:
            if waiver.issue_id not in issue_groups:
                issue_groups[waiver.issue_id] = []
            issue_groups[waiver.issue_id].append(waiver)
        
        # Find groups with multiple waivers
        duplicates = []
        for issue_id, waivers in issue_groups.items():
            if len(waivers) > 1:
                duplicates.append(waivers)
        
        self.logger.info(f"Found {len(duplicates)} sets of duplicate waivers")
        return duplicates
    
    def trigger_project_test(self, project_id: str) -> bool:
        """Trigger a test/rescan for a specific project (equivalent to 'Retest now' button)"""
        self.logger.info(f"Triggering test for project {project_id}")
        
        try:
            # Try REST API first (recommended approach)
            response = self._make_request(
                'POST',
                f'/rest/orgs/{self.org_id}/projects/{project_id}/test',
                params={'version': '2024-10-15'},
                headers={
                    'Content-Type': 'application/vnd.api+json',
                    'Accept': 'application/vnd.api+json'
                }
            )
            
            self.logger.info(f"Successfully triggered test for project {project_id}")
            return True
            
        except Exception as e:
            self.logger.warning(f"REST API test failed for project {project_id}, trying V1 API: {e}")
            
            # Fallback to V1 API if REST API fails
            try:
                response = self._make_request(
                    'POST',
                    f'/v1/org/{self.org_id}/project/{project_id}/test'
                )
                
                self.logger.info(f"Successfully triggered test for project {project_id} via V1 API")
                return True
                
            except Exception as e2:
                self.logger.error(f"Failed to trigger test for project {project_id} via both APIs: {e2}")
                return False
    
    def bulk_trigger_project_tests(self, project_ids: List[str]) -> Dict[str, bool]:
        """Trigger tests for multiple projects"""
        self.logger.info(f"Triggering tests for {len(project_ids)} projects")
        
        results = {}
        
        for project_id in project_ids:
            success = self.trigger_project_test(project_id)
            results[project_id] = success
            
            # Add a small delay to avoid overwhelming the API
            time.sleep(0.5)
        
        successful = sum(1 for success in results.values() if success)
        self.logger.info(f"Successfully triggered tests for {successful}/{len(project_ids)} projects")
        
        return results
    
    def get_project_test_status(self, project_id: str) -> Optional[Dict]:
        """Get the latest test status/results for a project"""
        try:
            # Get project details which includes last test information
            response = self._make_request(
                'GET',
                f'/rest/orgs/{self.org_id}/projects/{project_id}',
                params={'version': '2024-10-15'}
            )
            
            project_data = response.json()
            attrs = project_data.get('data', {}).get('attributes', {})
            
            return {
                'project_id': project_id,
                'name': attrs.get('name', 'Unknown'),
                'last_tested': attrs.get('last_tested_date'),
                'status': attrs.get('status', 'unknown'),
                'test_frequency': attrs.get('test_frequency', 'unknown')
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get test status for project {project_id}: {e}")
            return None


class SnykUtility:
    """Main utility class for Snyk operations"""
    
    def __init__(self, api_token: str, org_id: str):
        self.client = SnykAPIClient(api_token, org_id)
        self.logger = self.client.logger
        self.template_manager = WaiverTemplateManager()
    
    def load_project_ids(self, file_path: str) -> List[str]:
        """Load project IDs from a file (one per line)"""
        try:
            with open(file_path, 'r') as f:
                project_ids = [line.strip() for line in f if line.strip()]
            
            self.logger.info(f"Loaded {len(project_ids)} project IDs from {file_path}")
            return project_ids
            
        except Exception as e:
            self.logger.error(f"Failed to load project IDs from {file_path}: {e}")
            return []
    
    def check_distinct_issues(self, project_ids_file: str, output_file: Optional[str] = None):
        """Check for distinct issues across projects"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        distinct_issues = self.client.get_distinct_issues(project_ids)
        
        # Prepare output data
        issues_data = []
        for issue in distinct_issues:
            issues_data.append({
                'issue_id': issue.id,
                'title': issue.title,
                'severity': issue.severity,
                'type': issue.issue_type,
                'project_id': issue.project_id,
                'project_name': issue.project_name,
                'package_name': issue.package_name,
                'package_version': issue.package_version,
                'introduced_date': issue.introduced_date
            })
        
        # Sort by severity and title
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        issues_data.sort(key=lambda x: (severity_order.get(x['severity'], 4), x['title']))
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(issues_data, f, indent=2)
            self.logger.info(f"Issues data written to {output_file}")
        
        # Print summary
        print(f"\n=== DISTINCT ISSUES SUMMARY ===")
        print(f"Total distinct issues: {len(distinct_issues)}")
        
        severity_counts = {}
        for issue in distinct_issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            print(f"{severity.capitalize()}: {count}")
        
        return distinct_issues
    
    def list_active_waivers(self, project_ids_file: str, output_file: Optional[str] = None, 
                           show_expiring: bool = False):
        """List all active waivers with optional filtering"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        waivers = self.client.get_all_waivers(project_ids, active_only=True)
        
        if show_expiring:
            # Filter to show only waivers expiring in next 30 days
            cutoff_date = datetime.now() + timedelta(days=30)
            expiring_waivers = []
            
            for waiver in waivers:
                if waiver.expiry_date != 'unknown':
                    try:
                        expiry_date = datetime.fromisoformat(waiver.expiry_date.replace('Z', '+00:00'))
                        if expiry_date <= cutoff_date:
                            expiring_waivers.append(waiver)
                    except:
                        pass
            
            waivers = expiring_waivers
            print(f"\n=== WAIVERS EXPIRING IN NEXT 30 DAYS ===")
        else:
            print(f"\n=== ACTIVE WAIVERS ===")
        
        # Prepare output data
        waivers_data = []
        for waiver in waivers:
            waivers_data.append({
                'waiver_id': waiver.id,
                'issue_id': waiver.issue_id,
                'issue_title': waiver.issue_title,
                'issue_severity': waiver.issue_severity,
                'project_id': waiver.project_id,
                'project_name': waiver.project_name,
                'waiver_type': waiver.waiver_type,
                'reason': waiver.reason,
                'created_date': waiver.created_date,
                'expiry_date': waiver.expiry_date,
                'created_by': waiver.created_by,
                'is_active': waiver.is_active
            })
        
        # Sort by expiry date and severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        waivers_data.sort(key=lambda x: (
            x['expiry_date'] if x['expiry_date'] != 'unknown' else '9999-12-31',
            severity_order.get(x['issue_severity'], 4)
        ))
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(waivers_data, f, indent=2)
            self.logger.info(f"Waivers data written to {output_file}")
        
        # Print summary
        print(f"Total waivers: {len(waivers)}")
        
        # Count by severity
        severity_counts = {}
        for waiver in waivers:
            severity_counts[waiver.issue_severity] = severity_counts.get(waiver.issue_severity, 0) + 1
        
        print("\nBy Severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity.capitalize()}: {count}")
        
        # Count by type
        type_counts = {}
        for waiver in waivers:
            type_counts[waiver.waiver_type] = type_counts.get(waiver.waiver_type, 0) + 1
        
        print("\nBy Type:")
        for waiver_type, count in sorted(type_counts.items()):
            print(f"  {waiver_type}: {count}")
        
        return waivers
    
    def remove_waivers_by_issue(self, project_ids_file: str, issue_reference: str):
        """Remove waivers based on issue reference (ID or title pattern)"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        print(f"Searching for waivers matching: {issue_reference}")
        
        # Get matching waivers first to show user what will be removed
        all_waivers = self.client.get_all_waivers(project_ids, active_only=False)
        matching_waivers = []
        
        for waiver in all_waivers:
            if (issue_reference == waiver.issue_id or 
                issue_reference.lower() in waiver.issue_title.lower()):
                matching_waivers.append(waiver)
        
        if not matching_waivers:
            print("No matching waivers found.")
            return
        
        print(f"\nFound {len(matching_waivers)} matching waivers:")
        for i, waiver in enumerate(matching_waivers, 1):
            status = "ACTIVE" if waiver.is_active else "EXPIRED"
            print(f"{i:3d}. [{status}] {waiver.issue_title[:50]}... in {waiver.project_name}")
        
        # Confirm removal
        confirm = input(f"\nRemove all {len(matching_waivers)} waivers? (y/N): ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            return
        
        # Remove waivers
        results = self.client.bulk_remove_waivers_by_issue(issue_reference, project_ids)
        
        successful = sum(1 for success in results.values() if success)
        print(f"\nWaivers removed: {successful}/{len(matching_waivers)}")
    
    def show_waiver_statistics(self, project_ids_file: str):
        """Show comprehensive waiver statistics"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        stats = self.client.get_waiver_statistics(project_ids)
        
        print(f"\n=== WAIVER STATISTICS ===")
        print(f"Total waivers: {stats['total_waivers']}")
        print(f"Active waivers: {stats['active_waivers']}")
        print(f"Expired waivers: {stats['expired_waivers']}")
        print(f"Expiring soon (30 days): {stats['expiring_soon']}")
        
        print(f"\nBy Type:")
        for waiver_type, count in sorted(stats['by_type'].items()):
            print(f"  {waiver_type}: {count}")
        
        print(f"\nBy Severity:")
        for severity, count in sorted(stats['by_severity'].items()):
            print(f"  {severity.capitalize()}: {count}")
        
        print(f"\nTop Projects by Waiver Count:")
        sorted_projects = sorted(stats['by_project'].items(), key=lambda x: x[1], reverse=True)
        for project, count in sorted_projects[:10]:  # Top 10
            print(f"  {project}: {count}")
        
        if stats['expiring_soon_details']:
            print(f"\nWaivers Expiring Soon:")
            for waiver in stats['expiring_soon_details'][:10]:  # Show first 10
                print(f"  {waiver['issue_title'][:40]}... expires {waiver['expiry_date'][:10]}")
    
    def find_and_show_duplicates(self, project_ids_file: str):
        """Find and display duplicate waivers"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        duplicates = self.client.find_duplicate_waivers(project_ids)
        
        if not duplicates:
            print("No duplicate waivers found.")
            return
        
        print(f"\n=== DUPLICATE WAIVERS ===")
        print(f"Found {len(duplicates)} sets of duplicate waivers:")
        
        for i, waiver_group in enumerate(duplicates, 1):
            print(f"\n{i}. Issue: {waiver_group[0].issue_title}")
            print(f"   Issue ID: {waiver_group[0].issue_id}")
            print(f"   Severity: {waiver_group[0].issue_severity}")
            print(f"   Duplicate waivers ({len(waiver_group)}):")
            
            for waiver in waiver_group:
                status = "ACTIVE" if waiver.is_active else "EXPIRED"
                print(f"     - [{status}] {waiver.project_name} (expires: {waiver.expiry_date[:10] if waiver.expiry_date != 'unknown' else 'unknown'})")
        
        return duplicates
    
    def cleanup_expired_waivers(self, project_ids_file: str):
        """Remove all expired waivers"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        all_waivers = self.client.get_all_waivers(project_ids, active_only=False)
        expired_waivers = [w for w in all_waivers if not w.is_active]
        
        if not expired_waivers:
            print("No expired waivers found.")
            return
        
        print(f"Found {len(expired_waivers)} expired waivers.")
        confirm = input("Remove all expired waivers? (y/N): ")
        
        if confirm.lower() != 'y':
            print("Cancelled.")
            return
        
        removed_count = 0
        for waiver in expired_waivers:
            if self.client.remove_waiver(waiver.id, waiver.project_id):
                removed_count += 1
        
        print(f"Removed {removed_count}/{len(expired_waivers)} expired waivers.")
    
    def trigger_project_retests(self, project_ids_file: str, specific_projects: Optional[List[str]] = None):
        """Trigger retests for projects (equivalent to 'Retest now' button)"""
        if specific_projects:
            project_ids = specific_projects
            print(f"Triggering retests for {len(project_ids)} specified projects")
        else:
            project_ids = self.load_project_ids(project_ids_file)
            if not project_ids:
                return
            print(f"Triggering retests for {len(project_ids)} projects from file")
        
        print("This will trigger a new security scan for each project.")
        confirm = input("Proceed? (y/N): ")
        
        if confirm.lower() != 'y':
            print("Cancelled.")
            return
        
        results = self.client.bulk_trigger_project_tests(project_ids)
        
        successful = sum(1 for success in results.values() if success)
        failed = len(results) - successful
        
        print(f"\n=== RETEST RESULTS ===")
        print(f"✅ Successfully triggered: {successful}")
        print(f"❌ Failed: {failed}")
        
        if failed > 0:
            print(f"\nFailed projects:")
            for project_id, success in results.items():
                if not success:
                    print(f"  ❌ {project_id}")
        
        if successful > 0:
            print(f"\n📊 Test results will be available in the Snyk UI once scans complete.")
            print(f"    This typically takes a few minutes per project.")
    
    def check_project_test_status(self, project_ids_file: str):
        """Check the test status of projects"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        print(f"Checking test status for {len(project_ids)} projects...\n")
        
        for project_id in project_ids:
            status = self.client.get_project_test_status(project_id)
            if status:
                print(f"📋 {status['name'][:40]:<40} | Last tested: {status['last_tested'] or 'Never'} | Status: {status['status']}")
            else:
                print(f"❌ {project_id:<40} | Failed to retrieve status")
        
        print(f"\n✅ Status check complete for {len(project_ids)} projects")
    
    def retest_projects_with_issues(self, project_ids_file: str, severity_filter: Optional[str] = None):
        """Trigger retests only for projects that have issues of specified severity"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        print(f"Finding projects with issues (severity filter: {severity_filter or 'all'})...")
        
        projects_to_retest = []
        
        for project_id in project_ids:
            try:
                issues = self.client.get_project_issues(project_id)
                if severity_filter:
                    # Filter by severity
                    filtered_issues = [issue for issue in issues if issue.severity.lower() == severity_filter.lower()]
                    if filtered_issues:
                        projects_to_retest.append(project_id)
                        print(f"  ✓ {project_id}: {len(filtered_issues)} {severity_filter} issues")
                else:
                    # Any issues
                    if issues:
                        projects_to_retest.append(project_id)
                        print(f"  ✓ {project_id}: {len(issues)} total issues")
            except Exception as e:
                print(f"  ❌ {project_id}: Failed to check issues - {e}")
        
        if not projects_to_retest:
            filter_msg = f" with {severity_filter} severity" if severity_filter else ""
            print(f"No projects found with issues{filter_msg}.")
            return
        
        print(f"\nFound {len(projects_to_retest)} projects to retest")
        self.trigger_project_retests(None, projects_to_retest)
    
    def list_waiver_templates(self, category: Optional[str] = None):
        """List available waiver templates"""
        templates = self.template_manager.list_templates(category)
        
        if category:
            print(f"\n=== WAIVER TEMPLATES - {category.upper()} ===")
        else:
            print(f"\n=== WAIVER TEMPLATES ===")
        
        if not templates:
            print("No templates found.")
            return
        
        # Group by category
        by_category = {}
        for template in templates:
            if template.category not in by_category:
                by_category[template.category] = []
            by_category[template.category].append(template)
        
        for cat, cat_templates in sorted(by_category.items()):
            if not category:  # Only show category headers if not filtering
                print(f"\n{cat.upper()}:")
            
            for template in sorted(cat_templates, key=lambda x: x.name):
                print(f"  {template.name}")
                print(f"    Description: {template.description}")
                print(f"    Type: {template.waiver_type}")
                print(f"    Default duration: {template.default_days} days")
                print(f"    Justification: {template.justification}")
                print()
    
    def add_waiver_template(self):
        """Interactively add a new waiver template"""
        print("\n=== ADD WAIVER TEMPLATE ===")
        
        name = input("Template name (unique identifier): ").strip()
        if not name:
            print("Name is required.")
            return
        
        if self.template_manager.get_template(name):
            print(f"Template '{name}' already exists.")
            return
        
        description = input("Description: ").strip()
        if not description:
            print("Description is required.")
            return
        
        print("\nAvailable waiver types:")
        print("  - not-applicable: Issue doesn't apply")
        print("  - temporary: Temporary waiver with fix planned")
        print("  - wont-fix: Permanent acceptance of risk")
        
        waiver_type = input("Waiver type: ").strip()
        if waiver_type not in ['not-applicable', 'temporary', 'wont-fix']:
            print("Invalid waiver type.")
            return
        
        try:
            default_days = int(input("Default duration (days): "))
        except ValueError:
            print("Invalid number of days.")
            return
        
        justification = input("Default justification: ").strip()
        if not justification:
            print("Justification is required.")
            return
        
        print("\nAvailable categories:")
        categories = self.template_manager.get_categories()
        for cat in sorted(categories):
            print(f"  - {cat}")
        
        category = input("Category (or new category): ").strip()
        if not category:
            print("Category is required.")
            return
        
        template = WaiverTemplate(
            name=name,
            description=description,
            waiver_type=waiver_type,
            default_days=default_days,
            justification=justification,
            category=category
        )
        
        if self.template_manager.add_template(template):
            print(f"Template '{name}' added successfully.")
        else:
            print("Failed to add template.")
    
    def remove_waiver_template(self, template_name: str):
        """Remove a custom waiver template"""
        if self.template_manager.remove_template(template_name):
            print(f"Template '{template_name}' removed successfully.")
        else:
            print(f"Could not remove template '{template_name}'. It may be a built-in template or not exist.")
    
    def add_waivers_interactive_with_templates(self, project_ids_file: str):
        """Enhanced interactive waiver addition with template support"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        # Get distinct issues
        distinct_issues = self.client.get_distinct_issues(project_ids)
        issues_list = list(distinct_issues)
        
        if not issues_list:
            print("No issues found to waive.")
            return
        
        print(f"\nFound {len(issues_list)} distinct issues.")
        print("Select issues to waive:")
        
        # Display issues for selection
        for i, issue in enumerate(issues_list, 1):
            print(f"{i:3d}. [{issue.severity.upper():8s}] {issue.title[:60]}...")
        
        # Get user selection
        selection = input("\nEnter issue numbers (comma-separated) or 'all' for all issues: ")
        
        if selection.lower() == 'all':
            selected_issues = issues_list
        else:
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                selected_issues = [issues_list[i] for i in indices if 0 <= i < len(issues_list)]
            except ValueError:
                print("Invalid selection. Please enter numbers or 'all'.")
                return
        
        if not selected_issues:
            print("No issues selected.")
            return
        
        # Ask about waiver strategy
        print(f"\nWaiver strategy:")
        print("1. Add waivers only where issue exists and no active waiver (recommended)")
        print("2. Force add waivers everywhere (may create unnecessary waivers)")
        
        strategy = input("Choose strategy (1/2, default=1): ").strip() or "1"
        skip_if_waived = strategy == "1"
        
        # Choose between template and custom waiver
        print("\nWaiver options:")
        print("1. Use template")
        print("2. Custom waiver")
        
        choice = input("Choose option (1/2): ")
        
        if choice == '1':
            # Show available templates
            templates = self.template_manager.list_templates()
            print("\nAvailable templates:")
            for i, template in enumerate(templates, 1):
                print(f"{i:3d}. {template.name} - {template.description}")
            
            try:
                template_idx = int(input("Select template number: ")) - 1
                if 0 <= template_idx < len(templates):
                    template = templates[template_idx]
                    
                    # Option to override default days
                    override_days = input(f"Override default duration ({template.default_days} days)? Enter new value or press Enter to keep default: ")
                    days = int(override_days) if override_days.strip() else template.default_days
                    
                    # Add waivers using template
                    results = self.client.bulk_add_waivers(
                        selected_issues,
                        template.justification,
                        template.waiver_type,
                        days,
                        skip_if_waived
                    )
                    
                    self._print_waiver_results(results, template.name)
                else:
                    print("Invalid template selection.")
                    return
            except ValueError:
                print("Invalid template number.")
                return
                
        elif choice == '2':
            # Custom waiver (original logic)
            waiver_description = input("Enter waiver description: ")
            waiver_type = input("Enter waiver type (e.g., 'wont-fix', 'temporary', 'not-applicable'): ")
            
            try:
                days = int(input("Enter waiver duration in days: "))
            except ValueError:
                print("Invalid number of days.")
                return
            
            # Add waivers
            results = self.client.bulk_add_waivers(
                selected_issues,
                waiver_description,
                waiver_type,
                days,
                skip_if_waived
            )
            
            self._print_waiver_results(results, "custom waiver")
        else:
            print("Invalid choice.")
            return
    
    def _print_waiver_results(self, results: Dict[str, Dict[str, str]], waiver_type: str):
        """Print detailed results of waiver operations"""
        added = sum(1 for r in results.values() if r['status'] == 'added')
        skipped_waived = sum(1 for r in results.values() if r['status'] == 'skipped_existing_waiver')
        skipped_no_issue = sum(1 for r in results.values() if r['status'] == 'skipped_no_issue')
        failed = sum(1 for r in results.values() if r['status'] == 'failed')
        
        print(f"\n=== WAIVER RESULTS ({waiver_type}) ===")
        print(f"✅ Added: {added}")
        print(f"⏭️  Skipped (existing waiver): {skipped_waived}")
        print(f"⏭️  Skipped (issue not in project): {skipped_no_issue}")
        print(f"❌ Failed: {failed}")
        
        if skipped_waived > 0 or skipped_no_issue > 0 or failed > 0:
            print(f"\nDetailed breakdown:")
            for key, result in results.items():
                if result['status'] != 'added':
                    issue_project = key.split(':')
                    if len(issue_project) == 2:
                        issue_id, project_id = issue_project
                        print(f"  {result['status']}: {issue_id} in {project_id} - {result['reason']}")
                    else:
                        print(f"  {result['status']}: {key} - {result['reason']}")
    
    def add_waivers_by_issue_across_projects(self, project_ids_file: str, issue_reference: str,
                                           waiver_description: str, waiver_type: str, days: int):
        """Add waivers for a specific issue across multiple projects intelligently"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        print(f"Adding waivers for issue '{issue_reference}' across {len(project_ids)} projects")
        print("Only adding waivers where:")
        print("  1. The issue exists in the project")
        print("  2. No active waiver already exists")
        
        confirm = input(f"\nProceed? (y/N): ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            return
        
        results = self.client.bulk_add_waivers_by_project_list(
            project_ids,
            issue_reference,
            waiver_description,
            waiver_type,
            days,
            skip_if_waived=True
        )
        
        # Print detailed results
        added = sum(1 for r in results.values() if r['status'] == 'added')
        skipped_waived = sum(1 for r in results.values() if r['status'] == 'skipped_existing_waiver')
        skipped_no_issue = sum(1 for r in results.values() if r['status'] == 'skipped_no_issue')
        failed = sum(1 for r in results.values() if r['status'] == 'failed')
        
        print(f"\n=== PROJECT WAIVER RESULTS ===")
        print(f"✅ Added: {added}")
        print(f"⏭️  Skipped (existing waiver): {skipped_waived}")
        print(f"⏭️  Skipped (issue not found): {skipped_no_issue}")
        print(f"❌ Failed: {failed}")
        
        if self.logger.level <= logging.INFO:
            print(f"\nProject-by-project breakdown:")
            for project_id, result in results.items():
                status_emoji = {
                    'added': '✅',
                    'skipped_existing_waiver': '⏭️',
                    'skipped_no_issue': '⏭️',
                    'failed': '❌'
                }.get(result['status'], '❓')
                print(f"  {status_emoji} {project_id}: {result['reason']}")
    
    def add_waivers_from_template(self, project_ids_file: str, template_name: str, 
                                  custom_days: Optional[int] = None):
        """Add waivers using a template"""
        template = self.template_manager.get_template(template_name)
        if not template:
            print(f"Template '{template_name}' not found.")
            return
        
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        # Get distinct issues
        distinct_issues = self.client.get_distinct_issues(project_ids)
        issues_list = list(distinct_issues)
        
        if not issues_list:
            print("No issues found to waive.")
            return
        
        print(f"\nUsing template: {template.name}")
        print(f"Description: {template.description}")
        print(f"Type: {template.waiver_type}")
        
        days = custom_days if custom_days else template.default_days
        print(f"Duration: {days} days")
        print(f"Justification: {template.justification}")
        
        print(f"\nFound {len(issues_list)} distinct issues.")
        print("Smart waiver mode: Only adding waivers where issue exists and no active waiver present.")
        print("Select issues to waive:")
        
        # Display issues for selection
        for i, issue in enumerate(issues_list, 1):
            print(f"{i:3d}. [{issue.severity.upper():8s}] {issue.title[:60]}...")
        
        # Get user selection
        selection = input("\nEnter issue numbers (comma-separated) or 'all' for all issues: ")
        
        if selection.lower() == 'all':
            selected_issues = issues_list
        else:
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                selected_issues = [issues_list[i] for i in indices if 0 <= i < len(issues_list)]
            except ValueError:
                print("Invalid selection. Please enter numbers or 'all'.")
                return
        
        if not selected_issues:
            print("No issues selected.")
            return
        
        # Confirm action
        confirm = input(f"\nAdd smart waivers for {len(selected_issues)} issues using template '{template_name}'? (y/N): ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            return
        
        # Add waivers
        results = self.client.bulk_add_waivers(
            selected_issues,
            template.justification,
            template.waiver_type,
            days,
            skip_if_waived=True
        )
        
        # Print results
        self._print_waiver_results(results, f"template '{template_name}'")
    
    def add_waivers_interactive(self, project_ids_file: str):
        """Interactively add waivers for issues"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        # Get distinct issues
        distinct_issues = self.client.get_distinct_issues(project_ids)
        issues_list = list(distinct_issues)
        
        if not issues_list:
            print("No issues found to waive.")
            return
        
        print(f"\nFound {len(issues_list)} distinct issues.")
        print("Select issues to waive:")
        
        # Display issues for selection
        for i, issue in enumerate(issues_list, 1):
            print(f"{i:3d}. [{issue.severity.upper():8s}] {issue.title[:60]}...")
        
        # Get user selection
        selection = input("\nEnter issue numbers (comma-separated) or 'all' for all issues: ")
        
        if selection.lower() == 'all':
            selected_issues = issues_list
        else:
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                selected_issues = [issues_list[i] for i in indices if 0 <= i < len(issues_list)]
            except ValueError:
                print("Invalid selection. Please enter numbers or 'all'.")
                return
        
        if not selected_issues:
            print("No issues selected.")
            return
        
        # Get waiver details
        waiver_description = input("Enter waiver description: ")
        waiver_type = input("Enter waiver type (e.g., 'wont-fix', 'temporary', 'not-applicable'): ")
        
        try:
            days = int(input("Enter waiver duration in days: "))
        except ValueError:
            print("Invalid number of days.")
            return
        
        # Confirm action
        print(f"\nAbout to add waivers for {len(selected_issues)} issues:")
        print(f"Description: {waiver_description}")
        print(f"Type: {waiver_type}")
        print(f"Duration: {days} days")
        
        confirm = input("Proceed? (y/N): ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            return
        
        # Add waivers
        results = self.client.bulk_add_waivers(
            selected_issues, 
            waiver_description, 
            waiver_type, 
            days
        )
        
        # Print results
        successful = sum(1 for success in results.values() if success)
        print(f"\nWaivers added: {successful}/{len(selected_issues)}")


def main():
    parser = argparse.ArgumentParser(description='Snyk REST API Utility')
    parser.add_argument('--api-token', required=True, help='Snyk API token')
    parser.add_argument('--org-id', required=True, help='Snyk organization ID')
    parser.add_argument('--project-ids-file', required=True, help='File containing project IDs (one per line)')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Check issues command
    issues_parser = subparsers.add_parser('check-issues', help='Check for distinct issues')
    issues_parser.add_argument('--output', help='Output file for issues data (JSON)')
    
    # Add waivers command
    waivers_parser = subparsers.add_parser('add-waivers', help='Add waivers for issues')
    waivers_parser.add_argument('--description', help='Waiver description')
    waivers_parser.add_argument('--type', help='Waiver type')
    waivers_parser.add_argument('--days', type=int, help='Waiver duration in days')
    waivers_parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    
    # List waivers command
    list_waivers_parser = subparsers.add_parser('list-waivers', help='List active waivers')
    list_waivers_parser.add_argument('--output', help='Output file for waivers data (JSON)')
    list_waivers_parser.add_argument('--expiring', action='store_true', help='Show only waivers expiring in next 30 days')
    
    # Remove waivers command
    remove_waivers_parser = subparsers.add_parser('remove-waivers', help='Remove waivers by issue reference')
    remove_waivers_parser.add_argument('--issue-reference', required=True, help='Issue ID or title pattern to match')
    
    # Statistics command
    stats_parser = subparsers.add_parser('stats', help='Show waiver statistics')
    
    # Duplicates command
    duplicates_parser = subparsers.add_parser('find-duplicates', help='Find duplicate waivers')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup-expired', help='Remove all expired waivers')
    
    # Template management commands
    templates_parser = subparsers.add_parser('list-templates', help='List waiver templates')
    templates_parser.add_argument('--category', help='Filter by category')
    
    add_template_parser = subparsers.add_parser('add-template', help='Add a new waiver template')
    
    remove_template_parser = subparsers.add_parser('remove-template', help='Remove a waiver template')
    remove_template_parser.add_argument('--name', required=True, help='Template name to remove')
    
    template_waiver_parser = subparsers.add_parser('add-waivers-template', help='Add waivers using a template')
    template_waiver_parser.add_argument('--template', required=True, help='Template name to use')
    template_waiver_parser.add_argument('--days', type=int, help='Override template default days')
    
    # Cross-project waiver command
    cross_project_parser = subparsers.add_parser('add-waiver-cross-projects', help='Add waiver for specific issue across projects')
    cross_project_parser.add_argument('--issue-reference', required=True, help='Issue ID or title pattern')
    cross_project_parser.add_argument('--description', required=True, help='Waiver description')
    cross_project_parser.add_argument('--type', required=True, help='Waiver type')
    cross_project_parser.add_argument('--days', type=int, required=True, help='Waiver duration in days')
    
    # Project testing commands
    retest_parser = subparsers.add_parser('retest-projects', help='Trigger retests for projects (Retest now button)')
    retest_parser.add_argument('--projects', nargs='+', help='Specific project IDs to retest (overrides file)')
    
    test_status_parser = subparsers.add_parser('test-status', help='Check test status of projects')
    
    retest_issues_parser = subparsers.add_parser('retest-with-issues', help='Retest only projects with issues')
    retest_issues_parser.add_argument('--severity', choices=['low', 'medium', 'high', 'critical'], help='Filter by issue severity')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize utility
    utility = SnykUtility(args.api_token, args.org_id)
    
    if args.command == 'check-issues':
        utility.check_distinct_issues(args.project_ids_file, args.output)
    
    elif args.command == 'add-waivers':
        if args.interactive:
            utility.add_waivers_interactive_with_templates(args.project_ids_file)
        else:
            if not all([args.description, args.type, args.days]):
                print("Error: --description, --type, and --days are required for non-interactive mode")
                return
            
            # Get issues and add waivers
            project_ids = utility.load_project_ids(args.project_ids_file)
            distinct_issues = utility.client.get_distinct_issues(project_ids)
            
            results = utility.client.bulk_add_waivers(
                list(distinct_issues),
                args.description,
                args.type,
                args.days,
                skip_if_waived=True  # Default to smart mode
            )
            
            # Use new result format
            added = sum(1 for r in results.values() if r['status'] == 'added')
            print(f"Smart waivers added: {added}/{len(distinct_issues)}")
            if added < len(distinct_issues):
                utility._print_waiver_results(results, "batch mode")
    
    elif args.command == 'list-waivers':
        utility.list_active_waivers(args.project_ids_file, args.output, args.expiring)
    
    elif args.command == 'remove-waivers':
        utility.remove_waivers_by_issue(args.project_ids_file, args.issue_reference)
    
    elif args.command == 'stats':
        utility.show_waiver_statistics(args.project_ids_file)
    
    elif args.command == 'find-duplicates':
        utility.find_and_show_duplicates(args.project_ids_file)
    
    elif args.command == 'cleanup-expired':
        utility.cleanup_expired_waivers(args.project_ids_file)
    
    elif args.command == 'list-templates':
        utility.list_waiver_templates(args.category)
    
    elif args.command == 'add-template':
        utility.add_waiver_template()
    
    elif args.command == 'remove-template':
        utility.remove_waiver_template(args.name)
    
    elif args.command == 'add-waivers-template':
        utility.add_waivers_from_template(args.project_ids_file, args.template, args.days)


if __name__ == '__main__':
    main()
