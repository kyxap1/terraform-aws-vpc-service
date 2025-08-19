variable "name" {
  description = "Service name for resources"
  type        = string
  default     = "service"
}

variable "cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.83.0.0/16"
}

variable "azs" {
  description = "Availability zones"
  type        = list(string)
  default = [
    "us-east-1a",
    "us-east-1b"
  ]
}

variable "private_subnets" {
  description = "Private subnets for VPC"
  type        = list(string)
  default = [
    "10.83.1.0/24",
    "10.83.3.0/24"
  ]
}

variable "public_subnets" {
  description = "Public subnets for VPC"
  type        = list(string)
  default = [
    "10.83.0.0/24",
    "10.83.2.0/24"
  ]
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
}

variable "vpc_endpoint_tags" {
  description = "Tags for VPC endpoints"
  type        = map(string)
  default     = { endpoint = "true" }
}

variable "ingress_cidr_blocks" {
  description = "CIDR blocks allowed for ingress traffic"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "ingress_rules" {
  description = "Ingress rules for the security group"
  type        = list(string)
  default     = ["all-all"]
}

variable "egress_cidr_blocks" {
  description = "CIDR blocks allowed for egress traffic"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "egress_rules" {
  description = "Egress rules for the security group"
  type        = list(string)
  default     = ["all-all"]
}

variable "ami_ssm_parameter" {
  description = "SSM Parameter for the desired AMI"
  type        = string
  default     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

variable "ignore_ami_changes" {
  description = "Do not recreate instance on new AMI"
  type        = bool
  default     = true
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
}

variable "enable_monitoring" {
  description = "Enable detailed monitoring for instances"
  type        = bool
  default     = true
}

variable "metadata_options" {
  description = "Configuration for EC2 instance metadata service options"
  type        = map(any)
  default = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    instance_metadata_tags      = "enabled"
    http_put_response_hop_limit = 3
  }
}

variable "vpc_enabled" {
  description = "Enable VPC"
  type        = bool
  default     = true
}

variable "vpc_endpoints_enabled" {
  description = "Enable VPC endpoints"
  type        = bool
  default     = false
}

variable "keypair_enabled" {
  description = "Flag to enable or disable the creation of a key pair for instances"
  type        = bool
  default     = false
}

variable "bastion_enabled" {
  description = "Enable bastion instance"
  type        = bool
  default     = false
}

variable "sg_enabled" {
  description = "Enable security group"
  type        = bool
  default     = true
}

variable "service_enabled" {
  description = "Enable service instance"
  type        = bool
  default     = true
}

variable "bastion_private_ip" {
  description = "Defines what private IP address will be used by the bastion instance"
  type        = string
  default     = null
}

variable "service_private_ip" {
  description = "Defines what private IP address will be used by the service instance"
  type        = string
  default     = null
}

variable "user_data" {
  description = "The configuration to bbotstrap the instance"
  type        = string
  default     = null
}

variable "user_data_replace_on_change" {
  description = "Flag to determine if the instance should be replaced when user_data changes"
  type        = bool
  default     = true
}

variable "root_volume_size" {
  description = "The size for root ebs volume"
  type        = number
  default     = 8
}

variable "associate_public_ip_address" {
  description = "Whether to associate a public IP address with an instance in a VPC"
  type        = bool
  default     = null
}

# Spot instance request
variable "create_spot_instance" {
  description = "Depicts if the instance is a spot instance"
  type        = bool
  default     = false
}

variable "spot_price" {
  description = "The maximum price to request on the spot market. Defaults to on-demand price"
  type        = string
  default     = null
}

variable "spot_wait_for_fulfillment" {
  description = "If set, Terraform will wait for the Spot Request to be fulfilled, and will throw an error if the timeout of 10m is reached"
  type        = bool
  default     = null
}

variable "spot_type" {
  description = "If set to one-time, after the instance is terminated, the spot request will be closed. Default `persistent`"
  type        = string
  default     = null
}

variable "spot_launch_group" {
  description = "A launch group is a group of spot instances that launch together and terminate together. If left empty instances are launched and terminated individually"
  type        = string
  default     = null
}

variable "spot_instance_interruption_behavior" {
  description = "Indicates Spot instance behavior when it is interrupted. Valid values are `terminate`, `stop`, or `hibernate`"
  type        = string
  default     = null
}

variable "spot_valid_until" {
  description = "The end date and time of the request, in UTC RFC3339 format(for example, YYYY-MM-DDTHH:MM:SSZ)"
  type        = string
  default     = null
}

variable "spot_valid_from" {
  description = "The start date and time of the request, in UTC RFC3339 format(for example, YYYY-MM-DDTHH:MM:SSZ)"
  type        = string
  default     = null
}
