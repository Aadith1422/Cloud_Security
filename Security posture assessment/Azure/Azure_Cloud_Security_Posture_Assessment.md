# Azure Cloud Security Posture Assessment Report

**Prepared By:** Aadith C H\
**Platform:** Microsoft Azure\
**Region:** (Your Lab Region)\
**Date:** 28 February 2026

------------------------------------------------------------------------


## 1. Executive Summary

This report documents the security posture assessment performed on an
Azure lab environment using Microsoft Defender for Cloud.

The objective was to:

-   Enable Defender for Cloud recommendations\
-   Identify misconfigurations\
-   Classify risks by severity\
-   Remediate high-priority findings\
-   Validate post-remediation security status

------------------------------------------------------------------------

## 2. Environment Overview

-   Virtual Machines deployed\
-   Storage Account created\
-   Network Security Groups (NSGs) configured\
-   Azure Defender enabled

------------------------------------------------------------------------

## 3. Identified Security Findings

### Finding 1: Network Security Group Allows Public SSH Access

**Severity:** High\
**Resource:** Virtual Machine / NSG

**Description:**\
Port 22 (SSH) was open to 0.0.0.0/0 allowing unrestricted internet
access.

**Risk:**\
- Brute-force attacks\
- Unauthorized access\
- Increased attack surface

------------------------------------------------------------------------

### Finding 2: Storage Account Public Access Enabled

**Severity:** High\
**Resource:** Azure Storage Account

**Description:**\
Blob container access level allowed public read access.

**Risk:**\
- Data leakage\
- Unauthorized file access\
- Compliance violations



------------------------------------------------------------------------

### Finding 3: Missing Just-In-Time (JIT) VM Access

**Severity:** Medium\
**Description:**\
JIT VM access was not enabled for the virtual machine.

**Risk:**\
- Persistent open management ports\
- Increased exposure window


------------------------------------------------------------------------

## 4. Risk Classification Summary

| Finding              | Severity | Risk Level            |
|----------------------|----------|------------------------|
| Public SSH (NSG)     | High     | Critical Exposure      |
| Public Storage       | High     | Data Exposure          |
| Missing JIT Access   | Medium   | Operational Risk       |

------------------------------------------------------------------------

## 5. Remediation Steps

### Remediation 1: Restrict NSG SSH Access

**Steps Taken:**

1.  Navigate to Virtual Machine → Networking.\
2.  Open associated Network Security Group.\
3.  Edit inbound security rules.\
4.  Change source from 0.0.0.0/0 to trusted IP address.\
5.  Save changes.

**Security Improvement:**\
- Reduced attack surface\
- Enforced least privilege principle


------------------------------------------------------------------------

### Remediation 2: Disable Public Storage Access

**Steps Taken:**

1.  Navigate to Storage Account → Containers.\
2.  Change public access level to Private.\
3.  Enable "Allow Blob Public Access" = Disabled (if applicable).\
4.  Save configuration.

**Security Improvement:**\
- Prevented anonymous access\
- Reduced risk of data breach


------------------------------------------------------------------------

### Remediation 3: Enable Just-In-Time VM Access

**Steps Taken:**

1.  Navigate to Defender for Cloud → Workload Protections.\
2.  Enable Just-In-Time VM Access.\
3.  Configure allowed IP ranges and access duration.

**Security Improvement:**\
- Ports open only when required\
- Reduced exposure window



------------------------------------------------------------------------

## 6. Post-Remediation Validation

After applying fixes:

-   Defender for Cloud recommendations updated to healthy status\
-   No unrestricted SSH exposure\
-   No publicly accessible storage containers\
-   VM access controlled via JIT


------------------------------------------------------------------------

## 7. Before vs After Comparison

| Component        | Before              | After          |
|------------------|---------------------|---------------|
| NSG SSH          | Open to Internet    | Restricted     |
| Storage Access   | Public              | Private        |
| VM Access        | Always Open         | JIT Controlled |
| Secure Score     | Lower               | Improved       |

------------------------------------------------------------------------

## 8. Risk Reduction Impact

-   Reduced remote attack surface\
-   Prevented potential data leakage\
-   Improved Azure Secure Score\
-   Strengthened defense-in-depth strategy

------------------------------------------------------------------------

## 9. Conclusion

The Azure lab environment now aligns with Microsoft cloud security best
practices.\
The CSPM process demonstrated:

-   Detection of misconfigurations\
-   Risk prioritization\
-   Remediation implementation\
-   Compliance validation

This assessment reflects practical Azure cloud security hardening skills
aligned with industry standards.

------------------------------------------------------------------------

**End of Report**
