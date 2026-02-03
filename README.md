# 🔐 AWS IAM Policy Guide

Complete guide to AWS IAM Policies with examples - GitHub ready!

---

# AWS IAM Policy Complete Guide

![AWS](https://img.shields.io/badge/AWS-IAM-orange?logo=amazon-aws)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 📋 Table of Contents

- [Policy Types](#policy-types)
- [Policy Structure](#policy-structure)
- [Common Policies](#common-policies)
- [Service-Specific Policies](#service-specific-policies)
- [Policy Examples](#policy-examples)
- [Creating Policies](#creating-policies)
- [Best Practices](#best-practices)
- [Policy Generators](#policy-generators)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Policy Types

### 1. **Identity-Based Policies**
Attached to IAM users, groups, or roles

### 2. **Resource-Based Policies**
Attached to resources (S3 buckets, KMS keys, etc.)

### 3. **Permission Boundaries**
Set maximum permissions for IAM entities

### 4. **Service Control Policies (SCPs)**
Control permissions across AWS Organizations

### 5. **Session Policies**
Limit permissions for federated users or role sessions

### 6. **Access Control Lists (ACLs)**
Legacy permission model (S3, VPC)

---

## 📐 Policy Structure

### Basic Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "StatementID",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/username"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "us-east-1"
        }
      }
    }
  ]
}
```

### Components Explained

| Component | Required | Description |
|-----------|----------|-------------|
| `Version` | Yes | Policy language version |
| `Statement` | Yes | Array of permission statements |
| `Sid` | No | Statement ID (for reference) |
| `Effect` | Yes | `Allow` or `Deny` |
| `Principal` | Sometimes | Who the policy applies to |
| `Action` | Yes | What actions are allowed/denied |
| `Resource` | Yes | Which resources |
| `Condition` | No | When the policy applies |

---

## 🔑 Common Policies

### 1. **Read-Only Access**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:Get*",
        "s3:List*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "cloudwatch:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
```

### 2. **Admin Access**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

### 3. **Power User (No IAM)**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "account:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### 4. **MFA Required**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAllActionsWithMFA",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    },
    {
      "Sid": "DenyAllWithoutMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

---

## 🛠️ Service-Specific Policies

### **EC2 Policies**

#### Start/Stop EC2 Instances
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:RebootInstances",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

#### EC2 Full Access for Specific Region
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "us-east-1"
        }
      }
    }
  ]
}
```

#### Create EC2 with Specific Instance Types
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringEquals": {
          "ec2:InstanceType": ["t2.micro", "t2.small", "t3.micro"]
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": [
        "arn:aws:ec2:*:*:subnet/*",
        "arn:aws:ec2:*:*:network-interface/*",
        "arn:aws:ec2:*:*:volume/*",
        "arn:aws:ec2:*::image/*",
        "arn:aws:ec2:*:*:key-pair/*",
        "arn:aws:ec2:*:*:security-group/*"
      ]
    }
  ]
}
```

---

### **S3 Policies**

#### Read-Only Access to Specific Bucket
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }
  ]
}
```

#### Full Access to Specific Bucket
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }
  ]
}
```

#### S3 Bucket Policy (Resource-Based)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

#### S3 with Encryption Required
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    }
  ]
}
```

#### S3 Access by IP Address
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": [
            "192.168.1.0/24",
            "203.0.113.0/24"
          ]
        }
      }
    }
  ]
}
```

---

### **IAM Policies**

#### Allow Users to Manage Their Own Credentials
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:ChangePassword",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:ListAccessKeys",
        "iam:UpdateAccessKey",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": "arn:aws:iam::*:user/${aws:username}"
    }
  ]
}
```

#### Allow Creating IAM Roles with Permission Boundary
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:CreateRole",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/MyBoundary"
        }
      }
    }
  ]
}
```

---

### **RDS Policies**

#### RDS Read-Only Access
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds:Describe*",
        "rds:ListTagsForResource",
        "cloudwatch:GetMetricStatistics",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

#### RDS Snapshot Management
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds:CreateDBSnapshot",
        "rds:DeleteDBSnapshot",
        "rds:DescribeDBSnapshots",
        "rds:RestoreDBInstanceFromDBSnapshot",
        "rds:CopyDBSnapshot"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### **Lambda Policies**

#### Lambda Execution Role
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

#### Lambda Invoke Permission
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:InvokeFunction",
        "lambda:GetFunction"
      ],
      "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-function"
    }
  ]
}
```

---

### **EKS Policies**

#### EKS Cluster Management
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListClusters",
        "eks:DescribeNodegroup",
        "eks:ListNodegroups",
        "eks:AccessKubernetesApi"
      ],
      "Resource": "*"
    }
  ]
}
```

#### EKS Full Admin
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "eks:*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateInstanceProfile",
        "iam:DeleteInstanceProfile",
        "iam:GetRole",
        "iam:GetInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:AddRoleToInstanceProfile",
        "iam:PassRole",
        "iam:DetachRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:GetRolePolicy",
        "iam:GetOpenIDConnectProvider",
        "iam:CreateOpenIDConnectProvider",
        "iam:DeleteOpenIDConnectProvider",
        "iam:TagOpenIDConnectProvider",
        "iam:ListAttachedRolePolicies",
        "iam:TagRole"
      ],
      "Resource": [
        "arn:aws:iam::*:instance-profile/eks-*",
        "arn:aws:iam::*:role/eks-*",
        "arn:aws:iam::*:oidc-provider/*",
        "arn:aws:iam::*:role/aws-service-role/eks-nodegroup.amazonaws.com/AWSServiceRoleForAmazonEKSNodegroup",
        "arn:aws:iam::*:role/eksctl-*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "elasticloadbalancing:*",
        "autoscaling:*",
        "cloudformation:*"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### **CloudWatch Policies**

#### CloudWatch Logs Access
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

#### CloudWatch Metrics
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### **VPC Policies**

#### VPC Read-Only
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### **Secrets Manager**

#### Secrets Manager Access
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-*"
    }
  ]
}
```

---

### **KMS Policies**

#### KMS Key Usage
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    }
  ]
}
```

---

## 🎯 Advanced Policy Examples

### **Cross-Account Access**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::999999999999:root"
      },
      "Action": "sts:AssumeRole",
      "Resource": "*"
    }
  ]
}
```

### **Time-Based Access**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
        "DateGreaterThan": {
          "aws:CurrentTime": "2024-01-01T00:00:00Z"
        },
        "DateLessThan": {
          "aws:CurrentTime": "2024-12-31T23:59:59Z"
        }
      }
    }
  ]
}
```

### **Tag-Based Access Control**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/Environment": "Production",
          "ec2:ResourceTag/Owner": "${aws:username}"
        }
      }
    }
  ]
}
```

### **Deny All Except Specific Region**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
          ]
        }
      }
    }
  ]
}
```

---

## 🔧 Creating Policies

### **Using AWS CLI**

```bash
# Create policy from JSON file
aws iam create-policy \
  --policy-name MyPolicy \
  --policy-document file://policy.json

# Attach policy to user
aws iam attach-user-policy \
  --user-name myuser \
  --policy-arn arn:aws:iam::123456789012:policy/MyPolicy

# Attach policy to role
aws iam attach-role-policy \
  --role-name myrole \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# List attached policies
aws iam list-attached-user-policies --user-name myuser
```

### **Using Terraform**

```hcl
# Create IAM policy
resource "aws_iam_policy" "my_policy" {
  name        = "MyPolicy"
  description = "My custom policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::my-bucket",
          "arn:aws:s3:::my-bucket/*"
        ]
      }
    ]
  })
}

# Attach to user
resource "aws_iam_user_policy_attachment" "attach" {
  user       = aws_iam_user.myuser.name
  policy_arn = aws_iam_policy.my_policy.arn
}

# Attach to role
resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.myrole.name
  policy_arn = aws_iam_policy.my_policy.arn
}
```

### **Using CloudFormation**

```yaml
Resources:
  MyPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: MyPolicy
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - s3:GetObject
              - s3:ListBucket
            Resource:
              - arn:aws:s3:::my-bucket
              - arn:aws:s3:::my-bucket/*
      Users:
        - !Ref MyUser
```

---

## ✅ Best Practices

### 1. **Principle of Least Privilege**
```json
❌ Bad: "Action": "*"
✅ Good: "Action": ["s3:GetObject", "s3:ListBucket"]
```

### 2. **Use Managed Policies When Possible**
```bash
# AWS Managed Policies
arn:aws:iam::aws:policy/ReadOnlyAccess
arn:aws:iam::aws:policy/PowerUserAccess
```

### 3. **Use Policy Variables**
```json
{
  "Resource": "arn:aws:s3:::my-bucket/${aws:username}/*"
}
```

### 4. **Use Conditions**
```json
{
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": "203.0.113.0/24"
    }
  }
}
```

### 5. **Test Policies**
```bash
# Policy simulator
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/myuser \
  --action-names s3:GetObject \
  --resource-arns arn:aws:s3:::my-bucket/file.txt
```

### 6. **Regular Audits**
```bash
# List unused policies
aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/MyPolicy \
  --version-id v1

# Check last accessed
aws iam get-service-last-accessed-details \
  --job-id <job-id>
```

---

## 🛠️ Policy Generators & Tools

### **1. AWS Policy Generator**
[https://awspolicygen.s3.amazonaws.com/policygen.html](https://awspolicygen.s3.amazonaws.com/policygen.html)

### **2. IAM Policy Simulator**
```bash
# CLI
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/test \
  --action-names s3:GetObject \
  --resource-arns arn:aws:s3:::test-bucket/*
```

### **3. AWS Access Analyzer**
```bash
# Create analyzer
aws accessanalyzer create-analyzer \
  --analyzer-name my-analyzer \
  --type ACCOUNT

# List findings
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/my-analyzer
```

### **4. Policy Validation Script**

```bash
#!/bin/bash
# validate-policy.sh

POLICY_FILE=$1

# Validate JSON syntax
if ! jq empty "$POLICY_FILE" 2>/dev/null; then
    echo "❌ Invalid JSON syntax"
    exit 1
fi

# Check required fields
if ! jq -e '.Version' "$POLICY_FILE" >/dev/null; then
    echo "❌ Missing Version field"
    exit 1
fi

if ! jq -e '.Statement' "$POLICY_FILE" >/dev/null; then
    echo "❌ Missing Statement field"
    exit 1
fi

echo "✅ Policy is valid"
```

---

## 🐛 Troubleshooting

### **Check Effective Permissions**

```bash
# Check what actions a user can perform
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/myuser \
  --action-names ec2:DescribeInstances s3:ListBucket

# Check policy evaluation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=myuser
```

### **Common Issues**

#### 1. **Access Denied**
```bash
# Check attached policies
aws iam list-attached-user-policies --user-name myuser

# Check inline policies
aws iam list-user-policies --user-name myuser

# Get policy document
aws iam get-user-policy --user-name myuser --policy-name MyPolicy
```

#### 2. **Policy Too Large**
```
Maximum size:
- Identity-based: 6,144 characters
- Resource-based: 20,480 characters

Solution: Split into multiple policies or use managed policies
```

#### 3. **Invalid Principal**
```json
❌ "Principal": "arn:aws:iam::123456789012:user/myuser"
✅ "Principal": { "AWS": "arn:aws:iam::123456789012:user/myuser" }
```

---

## 📚 Quick Reference

### **Policy Variables**
```
${aws:username}        - IAM user name
${aws:userid}          - Unique ID
${aws:PrincipalArn}    - ARN of the principal
${aws:SourceIp}        - Source IP address
${aws:CurrentTime}     - Current time
${aws:RequestedRegion} - Requested region
```

### **Condition Operators**
```
StringEquals, StringNotEquals
StringLike, StringNotLike
NumericEquals, NumericNotEquals
NumericLessThan, NumericGreaterThan
DateEquals, DateNotEquals
DateLessThan, DateGreaterThan
Bool
IpAddress, NotIpAddress
ArnEquals, ArnNotEquals
```

---

## 🔗 Resources

- [AWS IAM Documentation](https://docs.aws.amazon.com/IAM/)
- [Policy Examples](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html)
- [Policy Simulator](https://policysim.aws.amazon.com/)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

---
