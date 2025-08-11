############################################
# IAM Role + Instance Profile for EC2
# - No static AWS keys on instance
# - Enables SSM (Systems Manager) for secure, audited access
############################################
resource "aws_iam_role" "ec2_role" {
  name = "vault-ssh-demo-ec2-role"

  # ✅ Allow EC2 to assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

# 📜 Attach SSM Core policy to enable Session Manager instead of SSH keys
resource "aws_iam_role_policy_attachment" "ec2_ssm_core" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# (Optional) Attach CloudWatch agent for logs/metrics
# resource "aws_iam_role_policy_attachment" "ec2_cw_agent" {
#   role       = aws_iam_role.ec2_role.name
#   policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
# }

# 🔗 Instance profile (binds IAM role to EC2 instance)
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "vault-ssh-demo-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

############################################
# Hardened EC2 Instance
# - Encrypted root volume
# - Enforce IMDSv2
# - Optimized I/O
# - Detailed monitoring
############################################
resource "aws_instance" "demo" {
  ami           = "ami-0c02fb55956c7d316" # Amazon Linux 2
  instance_type = "t3.micro"

  monitoring    = true # ✅ 1-min CloudWatch metrics (CKV_AWS_126)
  ebs_optimized = true # ✅ Optimized EBS I/O (CKV_AWS_135)

  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  tags = {
    Name        = "vault-ssh-demo"
    Environment = "POC"
  }

  # ✅ Enforce IMDSv2 to prevent SSRF attacks (CKV2_AWS_41)
  metadata_options {
    http_tokens = "required"
  }

  # ✅ Encrypt the root block device at rest
  root_block_device {
    encrypted = true
  }
}

############################################
# Vault SSH Certificate Request
# - Requests a short-lived cert from Vault's SSH CA
# - Cert is valid for 15 minutes only
# - Public key loaded from ~/.ssh/id_rsa.pub
############################################
data "vault_generic_endpoint" "ssh_cert" {
  path = "ssh/sign/terraform-ssh"

  # Vault token is provided at runtime via VAULT_TOKEN
  data_json = jsonencode({
    public_key = file("~/.ssh/id_rsa.pub")
    ttl        = "15m"
  })
}
