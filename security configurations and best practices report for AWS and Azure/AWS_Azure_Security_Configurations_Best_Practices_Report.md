# Cloud Security Configurations & Best Practices Report

## AWS & Microsoft Azure Hardening Guide

**Prepared By:** Aadith C H\
**Purpose:** Security Hardening & Governance Documentation\
**Scope:** AWS & Azure Cloud Infrastructure

------------------------------------------------------------------------

# 1. Executive Summary

This document outlines security hardening measures implemented across
AWS and Microsoft Azure environments, along with justification,
commands, maintenance checklists, and secure configuration templates.

Objectives:

-   Enforce Least Privilege (PoLP)
-   Secure identity and access management
-   Protect storage resources
-   Harden network configurations
-   Enable continuous monitoring and logging
-   Establish ongoing governance practices

------------------------------------------------------------------------

# 2. AWS Security Configurations

## 2.1 IAM Hardening

### Controls Implemented

-   Enforced MFA for all IAM users
-   Disabled root account usage
-   Removed wildcard "\*" permissions
-   Applied permission boundaries
-   Implemented role-based access instead of user-based permissions
-   Enforced access key rotation

### Secure IAM Policy Example

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/blog-users"
    }
  ]
}
```

### Justification

-   Reduces risk of privilege escalation
-   Limits blast radius during compromise
-   Prevents administrative abuse

------------------------------------------------------------------------

## 2.2 EC2 Hardening

### Controls Applied

-   Restricted SSH to trusted IP ranges
-   Disabled password authentication
-   Enforced key-based authentication
-   Enabled IMDSv2
-   Enabled EBS encryption

### Secure Security Group Rule

``` bash
aws ec2 authorize-security-group-ingress   --group-id sg-xxxx   --protocol tcp   --port 22   --cidr YOUR_IP/32
```

### Justification

-   Prevents brute-force attacks
-   Reduces exposure to internet-based threats
-   Protects instance metadata

------------------------------------------------------------------------

## 2.3 S3 Security

### Controls Applied

-   Enabled Block Public Access
-   Enforced HTTPS-only access
-   Enabled Server-Side Encryption (SSE)
-   Enabled bucket logging

### Secure Bucket Policy

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    }
  ]
}
```

### Justification

-   Prevents public exposure
-   Ensures encrypted data transmission
-   Enables auditing and forensic analysis

------------------------------------------------------------------------

## 2.4 Logging & Monitoring

### Services Enabled

-   CloudTrail (API logging)
-   AWS Config (compliance tracking)
-   GuardDuty (threat detection)
-   CloudWatch (monitoring & alerts)
-   Security Hub (centralized findings)

### Enable CloudTrail Example

``` bash
aws cloudtrail create-trail --name secure-trail --s3-bucket-name logs-bucket
```

------------------------------------------------------------------------

# 3. Azure Security Configurations

## 3.1 Azure RBAC & Identity

### Controls Applied

-   Removed Owner role from non-admin users
-   Replaced Contributor with custom minimal roles
-   Enabled Privileged Identity Management (PIM)
-   Implemented Managed Identity usage
-   Enabled Conditional Access policies

### Custom Role Example

``` json
{
  "Name": "CosmosDBReader",
  "IsCustom": true,
  "Actions": [
    "Microsoft.DocumentDB/databaseAccounts/read"
  ],
  "AssignableScopes": ["/subscriptions/SUB_ID"]
}
```

### Justification

-   Prevents privilege escalation
-   Enforces separation of duties
-   Reduces over-permissioning

------------------------------------------------------------------------

## 3.2 Azure Storage Hardening

### Controls Applied

-   Disabled public blob access
-   Enabled Private Endpoints
-   Enabled Storage firewall
-   Enabled encryption at rest
-   Enabled logging diagnostics

### Disable Public Access

``` bash
az storage account update   --name mystorage   --resource-group myRG   --allow-blob-public-access false
```

------------------------------------------------------------------------

## 3.3 Virtual Machine Hardening

### Controls Applied

-   Restricted NSG inbound rules
-   Disabled unnecessary public IP exposure
-   Enforced SSH key authentication
-   Enabled Microsoft Defender for Cloud

### Secure NSG Rule Example

``` bash
az network nsg rule create   --resource-group myRG   --nsg-name myNSG   --name AllowSSH   --protocol Tcp   --direction Inbound   --priority 100   --source-address-prefix YOUR_IP   --destination-port-range 22   --access Allow
```

------------------------------------------------------------------------

## 3.4 Logging & Monitoring

### Services Enabled

-   Azure Monitor
-   Activity Logs
-   Defender for Cloud
-   Log Analytics Workspace

------------------------------------------------------------------------

# 4. Ongoing Maintenance Checklist

## AWS Monthly Checklist

-   Rotate IAM access keys (every 90 days)
-   Review CloudTrail logs
-   Audit IAM roles and policies
-   Review Security Groups
-   Validate S3 public exposure settings
-   Review GuardDuty findings

## Azure Monthly Checklist

-   Review RBAC assignments
-   Audit Owner role usage
-   Review NSG rules
-   Rotate Storage & CosmosDB keys
-   Review Activity Logs
-   Validate PIM approvals

------------------------------------------------------------------------

# 5. Credential Rotation Policy

  Resource             Rotation Frequency
  -------------------- --------------------
  IAM Access Keys      90 Days
  Azure Storage Keys   90 Days
  CosmosDB Keys        90 Days
  SSH Keys             180 Days
  Admin Passwords      60 Days

------------------------------------------------------------------------

# 6. Secure Network Architecture Principles

-   Use private subnets
-   Avoid public SSH exposure
-   Use Bastion Host / Azure Bastion
-   Implement Web Application Firewall
-   Separate production and development environments
-   Apply Zero Trust architecture

------------------------------------------------------------------------

# 7. Governance & Compliance Controls

## AWS

-   Service Control Policies (SCP)
-   IAM Access Analyzer
-   AWS Config Rules
-   Security Hub

## Azure

-   Azure Policy
-   Blueprint definitions
-   Conditional Access
-   Privileged Identity Management

------------------------------------------------------------------------

# 8. Conclusion

The implemented hardening measures significantly reduce risk of:

-   Privilege escalation
-   Credential abuse
-   Storage misconfiguration
-   Public exposure
-   Lateral movement

Continuous monitoring, strict IAM/RBAC governance, periodic audits, and
automated compliance enforcement are essential to maintaining secure
cloud environments.

------------------------------------------------------------------------

# End of Report
