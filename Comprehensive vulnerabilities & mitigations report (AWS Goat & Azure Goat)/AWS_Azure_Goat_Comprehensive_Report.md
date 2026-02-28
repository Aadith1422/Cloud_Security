# Cloud Penetration Testing Report

## AWS Goat & AzureGoat Comprehensive Vulnerability & Mitigation Assessment

**Author:** Aadith C H\
**Assessment Dates:** 2026-02-25 to 2026-02-26\
**Environment:** Terraform-Deployed AWS Goat & AzureGoat Labs\
**Overall Severity:** CRITICAL

------------------------------------------------------------------------

# 1. Executive Summary

This report presents the findings of a full-spectrum cloud penetration
test conducted against two intentionally vulnerable cloud environments:

-   AWS Goat (Amazon Web Services)
-   AzureGoat (Microsoft Azure)

Both environments were deployed using Infrastructure-as-Code (Terraform)
and were assessed to simulate real-world enterprise cloud deployments.

The assessment identified multiple high-risk vulnerabilities across:

-   Application Layer
-   Cloud Identity & Access Management
-   Storage Configurations
-   Network Exposure
-   Secret Management
-   Privilege Escalation Paths

In both cases, the attack chain resulted in complete administrative
control of the cloud environments.

## 1.1 Business Risk Overview

If these findings were present in a production environment, potential
impacts would include:

-   Full customer data breach
-   Cloud infrastructure destruction
-   Persistent attacker backdoor access
-   Regulatory non-compliance (GDPR, ISO 27001, SOC 2)
-   Reputational damage
-   Financial loss

------------------------------------------------------------------------

# 2. Assessment Methodology

The engagement followed industry-standard penetration testing
methodology:

1.  Reconnaissance
2.  Vulnerability Identification
3.  Exploitation
4.  Privilege Escalation
5.  Post-Exploitation & Impact Validation
6.  Remediation Planning

Testing was conducted in a controlled lab environment designed for
security research and educational purposes.

------------------------------------------------------------------------

# 3. AWS Goat -- Detailed Findings

## 3.1 Reflected Cross-Site Scripting (XSS)

### Description

User input was reflected directly into HTTP responses without proper
sanitization or output encoding.

### Proof of Concept

``` html
<script>alert(1)</script>
```

### Risk

-   Session hijacking
-   Cookie theft
-   Credential harvesting
-   Malicious script injection

### Root Cause

-   Missing output encoding
-   No Content Security Policy (CSP)
-   Lack of input validation

### Remediation

-   Encode user-controlled output
-   Implement strict CSP headers
-   Use modern frontend frameworks with auto-escaping
-   Perform security code review

------------------------------------------------------------------------

## 3.2 SQL Injection

### Description

User input was concatenated directly into SQL queries.

### Payload Used

    ' OR '1'='1

### Impact

-   Full database dump
-   Password hash extraction
-   Sensitive data exposure

### Secure Implementation

``` javascript
db.query("SELECT * FROM users WHERE email = ?", [email])
```

### Remediation

-   Use prepared statements
-   Avoid dynamic query construction
-   Implement input validation
-   Deploy Web Application Firewall (WAF)

------------------------------------------------------------------------

## 3.3 SSRF → AWS Credential Extraction

### Description

The application allowed arbitrary URL fetching via backend Lambda.

### Payload

    file:///proc/self/environ

### Credentials Extracted

-   AWS_ACCESS_KEY_ID
-   AWS_SECRET_ACCESS_KEY
-   AWS_SESSION_TOKEN

### Impact

-   Lambda execution role compromise
-   Cloud-wide resource abuse
-   Lateral movement to DynamoDB, S3, EC2

### Remediation

-   Restrict allowed URL schemes
-   Block internal IP ranges
-   Enforce IMDSv2
-   Remove sensitive data from environment variables
-   Use AWS Secrets Manager

------------------------------------------------------------------------

## 3.4 S3 Bucket Misconfiguration

### Description

Sensitive SSH private keys were stored in an accessible S3 bucket.

### Impact

-   Direct server access
-   Infrastructure compromise

### Secure Bucket Policy Example

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::dev-bucket/*",
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    }
  ]
}
```

### Remediation

-   Enable S3 Block Public Access
-   Enforce least privilege IAM policies
-   Remove secrets from object storage
-   Enable logging & monitoring

------------------------------------------------------------------------

## 3.5 IAM Privilege Escalation

### Description

Over-permissioned IAM policy allowed:

-   iam:CreatePolicy
-   iam:AttachRolePolicy
-   iam:PassRole
-   Resource: "\*"

### Impact

-   Creation of admin-level policy
-   Full AWS account takeover

### Remediation

-   Remove wildcard permissions
-   Apply permission boundaries
-   Implement AWS Organizations SCP
-   Monitor IAM changes via CloudTrail

------------------------------------------------------------------------

# 4. AzureGoat -- Detailed Findings

## 4.1 Public Blob Storage Exposure

### Description

Development container allowed public list/read access.

### Exploit

    ?restype=container&comp=list

### Impact

-   SSH key exposure
-   Infrastructure mapping
-   Data leakage

### Remediation

-   Disable public access
-   Enable Storage firewall
-   Use Private Endpoints
-   Enforce Azure Policy restrictions

------------------------------------------------------------------------

## 4.2 SSRF → Configuration Disclosure

### Payload

    file:///home/site/wwwroot/local.settings.json

### Exposed Secrets

-   CosmosDB Primary Key
-   Storage Account Key
-   JWT Secret

### Impact

-   Database compromise
-   Application privilege escalation
-   Source code extraction

### Remediation

-   Use Managed Identity
-   Store secrets in Azure Key Vault
-   Restrict file protocol access
-   Implement outbound traffic filtering

------------------------------------------------------------------------

## 4.3 Managed Identity Abuse

### Command Used

    az login -i

### Impact

-   Resource enumeration
-   Abuse of Contributor permissions

### Remediation

-   Apply least privilege RBAC
-   Use custom minimal roles
-   Implement Privileged Identity Management (PIM)

------------------------------------------------------------------------

## 4.4 Automation Account Privilege Escalation

### Description

Automation Account had Owner privileges at Resource Group level.

Runbook modified to assign Owner role to attacker-controlled identity.

### Impact

-   Full Resource Group control
-   Ability to modify RBAC
-   Infrastructure takeover

### Remediation

-   Remove Owner role from automation identities
-   Enforce separation of duties
-   Enable Activity Log alerts
-   Implement Azure Policy governance

------------------------------------------------------------------------

# 5. Consolidated Risk Assessment

  Category          Risk
  ----------------- ------
  Confidentiality   High
  Integrity         High
  Availability      High

Overall Severity: CRITICAL

Attack chains demonstrated complete breakdown of:

-   Identity governance
-   Secret management
-   Network segmentation
-   Least privilege enforcement

------------------------------------------------------------------------

# 6. Remediation Roadmap

## Immediate (0--24 Hours)

-   Rotate exposed credentials
-   Remove Owner/IAM escalation permissions
-   Disable public storage access

## Short-Term (1--3 Days)

-   Restrict SSH to trusted IPs
-   Apply least privilege IAM/RBAC
-   Enable logging & monitoring

## Medium-Term (1 Week)

-   Implement Secrets Manager / Key Vault
-   Enforce policy-based governance
-   Conduct full IAM/RBAC audit

## Long-Term (30 Days)

-   Implement Zero Trust model
-   Automate compliance scanning
-   Deploy SIEM monitoring
-   Conduct periodic penetration testing

------------------------------------------------------------------------

# 7. Conclusion

The AWS Goat and AzureGoat environments demonstrated how small
misconfigurations can escalate into full cloud compromise.

The most critical lessons:

-   SSRF is a cloud pivot vulnerability
-   Secrets must never be stored in runtime configs
-   IAM/RBAC over-permissioning is catastrophic
-   Storage misconfiguration leads to infrastructure breach
-   Least privilege is non-negotiable in cloud security

Immediate remediation and long-term governance implementation are
strongly recommended.

------------------------------------------------------------------------

# End of Expanded Report