#!/usr/bin/env python3
"""
Snyk REST API Utility

A comprehensive utility for interacting with Snyk's REST API to:
1. Check for distinct issues across multiple projects
2. Add waivers for issues with customizable parameters
3. Manage waiver templates
4. Trigger project retests

Usage:
    python3 snyk_utility.py --help
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
import ssl
import certifi

# Configure SSL context for certificate issues
try:
    import certifi
    # Set the SSL certificate bundle
    import os
    os.environ['REQUESTS_CA_BUNDLE'] = certifi.where()
    os.environ['SSL_CERT_FILE'] = certifi.where()
except ImportError:
    print("Warning: certifi not available, SSL verification might fail")
    print("Install with: pip3 install certifi")


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
                name="compensating_controls",
                description="Compensating Controls - Alternative protections in place",
                waiver_type="wont-fix",
                default_days=365,
                justification="Compensating security controls are in place that mitigate this vulnerability.",
                category="mitigation"
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
        if self.get_template(template.name):
            return False
        
        self.templates.append(template)
        self.save_custom_templates()
        return True
    
    def remove_template(self, name: str) -> bool:
        """Remove a custom template"""
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
        
        # Configure SSL verification
        try:
            self.session.verify = certifi.where()
        except:
            # If certifi is not available, disable SSL verification as last resort
            print("Warning: SSL verification disabled due to certificate issues")
            print("For security, please install certificates: pip3 install certifi")
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
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
                
                if response.status_code == 429:
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
            project_response = self._make_request(
                'GET', 
                f'/rest/orgs/{self.org_id}/projects/{project_id}'
            )
            project_data = project_response.json()
            project_name = project_data.get('data', {}).get('attributes', {}).get('name', 'Unknown')
            
            issues_response = self._make_request(
                'GET',
                f'/rest/orgs/{self.org_id}/issues',
                params={
                    'project_id': project_id,
                    'limit': 1000
                }
            )
            
            issues_data = issues_response.json()
            issues = []
            
            for issue_data in issues_data.get('data', []):
                attrs = issue_data.get('attributes', {})
                
                package_name = 'Unknown'
                package_version = 'Unknown'
                
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
                    project_name='',
                    reason=attrs.get('reason', ''),
                    waiver_type=attrs.get('waiver_type', ''),
                    created_date=attrs.get('created', ''),
                    expiry_date=attrs.get('expiry', ''),
                    created_by=attrs.get('created_by', ''),
                    is_active=is_active,
                    issue_title='',
                    issue_severity=''
                )
                waivers.append(waiver)
            
            return waivers
            
        except Exception as e:
            self.logger.error(f"Failed to get existing waivers for issue {issue_id}: {e}")
            return []
    
    def smart_add_waiver(self, issue_id: str, project_id: str, waiver_description: str, 
                        waiver_type: str, days: int, skip_if_waived: bool = True) -> Dict[str, str]:
        """Intelligently add a waiver, checking for existing waivers and issue existence"""
        self.logger.debug(f"Smart waiver check for issue {issue_id} in project {project_id}")
        
        try:
            issue_response = self._make_request(
                'GET',
                f'/rest/orgs/{self.org_id}/projects/{project_id}/issues/{issue_id}'
            )
        except Exception as e:
            self.logger.debug(f"Issue {issue_id} not found in project {project_id}: {e}")
            return {'status': 'skipped_no_issue', 'reason': 'Issue not found in this project'}
        
        if skip_if_waived:
            existing_waivers = self.get_existing_waivers_for_issue(issue_id, project_id)
            active_waivers = [w for w in existing_waivers if w.is_active]
            
            if active_waivers:
                self.logger.debug(f"Active waiver already exists for issue {issue_id} in project {project_id}")
                return {
                    'status': 'skipped_existing_waiver', 
                    'reason': f'Active waiver already exists (expires: {active_waivers[0].expiry_date})'
                }
        
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
        
        added = sum(1 for r in results.values() if r['status'] == 'added')
        skipped_waived = sum(1 for r in results.values() if r['status'] == 'skipped_existing_waiver')
        skipped_no_issue = sum(1 for r in results.values() if r['status'] == 'skipped_no_issue')
        failed = sum(1 for r in results.values() if r['status'] == 'failed')
        
        self.logger.info(f"Waiver results - Added: {added}, Skipped (existing waiver): {skipped_waived}, "
                        f"Skipped (no issue): {skipped_no_issue}, Failed: {failed}")
        
        return results
    
    def trigger_project_test(self, project_id: str) -> bool:
        """Trigger a test/rescan for a specific project"""
        self.logger.info(f"Triggering test for project {project_id}")
        
        try:
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
            time.sleep(0.5)
        
        successful = sum(1 for success in results.values() if success)
        self.logger.info(f"Successfully triggered tests for {successful}/{len(project_ids)} projects")
        
        return results


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
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        issues_data.sort(key=lambda x: (severity_order.get(x['severity'], 4), x['title']))
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(issues_data, f, indent=2)
            self.logger.info(f"Issues data written to {output_file}")
        
        print(f"\n=== DISTINCT ISSUES SUMMARY ===")
        print(f"Total distinct issues: {len(distinct_issues)}")
        
        severity_counts = {}
        for issue in distinct_issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            print(f"{severity.capitalize()}: {count}")
        
        return distinct_issues
    
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
        
        by_category = {}
        for template in templates:
            if template.category not in by_category:
                by_category[template.category] = []
            by_category[template.category].append(template)
        
        for cat, cat_templates in sorted(by_category.items()):
            if not category:
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
        
        for i, issue in enumerate(issues_list, 1):
            print(f"{i:3d}. [{issue.severity.upper():8s}] {issue.title[:60]}...")
        
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
        
        confirm = input(f"\nAdd smart waivers for {len(selected_issues)} issues using template '{template_name}'? (y/N): ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            return
        
        results = self.client.bulk_add_waivers(
            selected_issues,
            template.justification,
            template.waiver_type,
            days,
            skip_if_waived=True
        )
        
        self._print_waiver_results(results, f"template '{template_name}'")
    
    def add_waivers_interactive_with_templates(self, project_ids_file: str):
        """Enhanced interactive waiver addition with template support"""
        project_ids = self.load_project_ids(project_ids_file)
        if not project_ids:
            return
        
        distinct_issues = self.client.get_distinct_issues(project_ids)
        issues_list = list(distinct_issues)
        
        if not issues_list:
            print("No issues found to waive.")
            return
        
        print(f"\nFound {len(issues_list)} distinct issues.")
        print("Select issues to waive:")
        
        for i, issue in enumerate(issues_list, 1):
            print(f"{i:3d}. [{issue.severity.upper():8s}] {issue.title[:60]}...")
        
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
        
        print(f"\nWaiver strategy:")
        print("1. Add waivers only where issue exists and no active waiver (recommended)")
        print("2. Force add waivers everywhere (may create unnecessary waivers)")
        
        strategy = input("Choose strategy (1/2, default=1): ").strip() or "1"
        skip_if_waived = strategy == "1"
        
        print("\nWaiver options:")
        print("1. Use template")
        print("2. Custom waiver")
        
        choice = input("Choose option (1/2): ")
        
        if choice == '1':
            templates = self.template_manager.list_templates()
            print("\nAvailable templates:")
            for i, template in enumerate(templates, 1):
                print(f"{i:3d}. {template.name} - {template.description}")
            
            try:
                template_idx = int(input("Select template number: ")) - 1
                if 0 <= template_idx < len(templates):
                    template = templates[template_idx]
                    
                    override_days = input(f"Override default duration ({template.default_days} days)? Enter new value or press Enter to keep default: ")
                    days = int(override_days) if override_days.strip() else template.default_days
                    
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
            waiver_description = input("Enter waiver description: ")
            waiver_type = input("Enter waiver type (e.g., 'wont-fix', 'temporary', 'not-applicable'): ")
            
            try:
                days = int(input("Enter waiver duration in days: "))
            except ValueError:
                print("Invalid number of days.")
                return
            
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
    
    # Template management commands
    templates_parser = subparsers.add_parser('list-templates', help='List waiver templates')
    templates_parser.add_argument('--category', help='Filter by category')
    
    add_template_parser = subparsers.add_parser('add-template', help='Add a new waiver template')
    
    remove_template_parser = subparsers.add_parser('remove-template', help='Remove a waiver template')
    remove_template_parser.add_argument('--name', required=True, help='Template name to remove')
    
    template_waiver_parser = subparsers.add_parser('add-waivers-template', help='Add waivers using a template')
    template_waiver_parser.add_argument('--template', required=True, help='Template name to use')
    template_waiver_parser.add_argument('--days', type=int, help='Override template default days')
    
    # Project testing commands
    retest_parser = subparsers.add_parser('retest-projects', help='Trigger retests for projects (Retest now button)')
    retest_parser.add_argument('--projects', nargs='+', help='Specific project IDs to retest (overrides file)')
    
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
            
            project_ids = utility.load_project_ids(args.project_ids_file)
            distinct_issues = utility.client.get_distinct_issues(project_ids)
            
            results = utility.client.bulk_add_waivers(
                list(distinct_issues),
                args.description,
                args.type,
                args.days,
                skip_if_waived=True
            )
            
            added = sum(1 for r in results.values() if r['status'] == 'added')
            print(f"Smart waivers added: {added}/{len(distinct_issues)}")
            if added < len(distinct_issues):
                utility._print_waiver_results(results, "batch mode")
    
    elif args.command == 'list-templates':
        utility.list_waiver_templates(args.category)
    
    elif args.command == 'add-template':
        utility.add_waiver_template()
    
    elif args.command == 'remove-template':
        utility.remove_waiver_template(args.name)
    
    elif args.command == 'add-waivers-template':
        utility.add_waivers_from_template(args.project_ids_file, args.template, args.days)
    
    elif args.command == 'retest-projects':
        utility.trigger_project_retests(args.project_ids_file, args.projects)


if __name__ == '__main__':
    main()