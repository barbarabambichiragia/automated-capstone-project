# VPC CIDR 
variable "aws_vpc" {
  default = "10.0.0.0/16"
}

#Public Subnet 1
variable "aws_pubsub01" {
  default = "10.0.1.0/24"
}

#Public Subnet 2
variable "aws_pubsub02" {
  default = "10.0.2.0/24"
}

#Private Subnet 1
variable "aws_prvsub01" {
  default = "10.0.3.0/24"
}

#Private Subnet 2
variable "aws_prvsub02" {
  default = "10.0.4.0/24"
}

#All IP CIDR
variable "all_ip" {
  default = "0.0.0.0/0"
}

#Username
variable "db_username" {
  default = "admin"
}

#Password
variable "db_password" {
  default = "EuTeam1password"
}
 

variable "acpet1-key" {
  default = "C:/Users/admin/Documents/Devops/Automated-Capstone-Project-EU-Team-1-15AUG/variable.acpet1-key.pub"
}
 
variable "ami" {
  default = "ami-035c5dc086849b5de"
}
 
