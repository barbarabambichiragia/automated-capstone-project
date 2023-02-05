# Create VPC
resource "aws_vpc" "acpet1_vpc" {
  cidr_block = var.aws_vpc

  tags = {
    Name = "acpet1_vpc"
  }
}

##2 Public Subnets
# Public Subnet 1
resource "aws_subnet" "acpet1_pubsn_01" {
  vpc_id            = aws_vpc.acpet1_vpc.id
  cidr_block        = var.aws_pubsub01
  availability_zone = "eu-west-2a"
  tags = {
    Name = "acpet1_pubsn_01"
  }
}       

# Public Subnet 2
resource "aws_subnet" "acpet1_pubsn_02" {
  vpc_id            = aws_vpc.acpet1_vpc.id
  cidr_block        = var.aws_pubsub02
  availability_zone = "eu-west-2b"
  tags = {
    Name = "acpet1_pubsn_02"
  }
}

##2 Private Subnets
# Private Subnet 1
resource "aws_subnet" "acpet1_prvsn_01" {
  vpc_id            = aws_vpc.acpet1_vpc.id
  cidr_block        = var.aws_prvsub01
  availability_zone = "eu-west-2a"
  tags = {
    Name = "acpet1_prvsn_01"
  }
}

#Private Subnet 2
resource "aws_subnet" "acpet1_prvsn_02" {
  vpc_id            = aws_vpc.acpet1_vpc.id
  cidr_block        = var.aws_prvsub02
  availability_zone = "eu-west-2b"
  tags = {
    Name = "acpet1_prvsn_02"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "acpet1_igw" {
  vpc_id = aws_vpc.acpet1_vpc.id

  tags = {
    Name = "acpet1_igw"
  }
}

# Create Elastic IP
resource "aws_eip" "acpet1_eip" {
  vpc = true

  tags = {
    Name = "acpet1_eip"
  }
}

# Create Elastic IP
resource "aws_nat_gateway" "acpet1_natgw" {
  allocation_id = aws_eip.acpet1_eip.id
  subnet_id     = aws_subnet.acpet1_pubsn_01.id

  tags = {
    Name = "acpet1_natgw"
  }
}

# Create Public Route Table
resource "aws_route_table" "acpet1_rtpublic" {
  vpc_id = aws_vpc.acpet1_vpc.id

  route {
    cidr_block = "0.0.0.0/0"

    gateway_id = aws_internet_gateway.acpet1_igw.id
  }
  tags = {
    Name = "acpet1_rtpublic"
  }
}

# Create Private Route Table
resource "aws_route_table" "acpet1_rtprivate" {
  vpc_id = aws_vpc.acpet1_vpc.id

  route {
    cidr_block = "0.0.0.0/0"

    gateway_id = aws_nat_gateway.acpet1_natgw.id
  }
  tags = {
    Name = "acpet1_rtprivate"
  }
}

# Create Route Table Association for Public Subnet1
resource "aws_route_table_association" "PSubnet_association1" {
  subnet_id      = aws_subnet.acpet1_pubsn_01.id
  route_table_id = aws_route_table.acpet1_rtpublic.id
}
# Create Route Table Association for Public Subnet2
resource "aws_route_table_association" "PSubnet_association2" {
  subnet_id      = aws_subnet.acpet1_pubsn_02.id
  route_table_id = aws_route_table.acpet1_rtpublic.id
}

# Create Route Table Association for Private Subnet1
resource "aws_route_table_association" "PrSubnet_association3" {
  subnet_id      = aws_subnet.acpet1_prvsn_01.id
  route_table_id = aws_route_table.acpet1_rtprivate.id
}

# Create Route Table Association for Public Subnet2
resource "aws_route_table_association" "PrSubnet_association4" {
  subnet_id      = aws_subnet.acpet1_prvsn_02.id
  route_table_id = aws_route_table.acpet1_rtprivate.id
}

##Create Two security groups
#Security group for frontend servers (Allows http and ssh)
resource "aws_security_group" "acpet1_frontend_sg" {
  name        = "acpet1_frontend_sg"
  description = "Allow HTTP and SSH inbound traffic"
  vpc_id      = aws_vpc.acpet1_vpc.id
  ingress {
    description = "Allow http traffic"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Allow ssh traffic"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "acpet1_frontend_sg"
  }
}

#Security group for backend servers (Allows from frontend_sg)
resource "aws_security_group" "acpet1_backend_sg" {
  name        = "acpet1_backend_sg"
  description = "Allow traffic from frontend sg"
  vpc_id      = aws_vpc.acpet1_vpc.id
  ingress {
    description = "Allow ssh traffic"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.aws_pubsub01}", "${var.aws_pubsub02}"]
  }
  ingress {
    description = "Allow mysql traffic"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["${var.aws_pubsub01}", "${var.aws_pubsub02}"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "acpet1_backend_sg"
  }
}

#create s3 media bucket
resource "aws_s3_bucket" "acpet1-mediabucket" {
  bucket = "acpet1-media-bucket"
  force_destroy = true
  tags = {
    Name        = "acpet1-media-bucket"
    Environment = "Dev"
  }
}
#public access enabled
resource "aws_s3_bucket_public_access_block" "Public_access" {
  bucket                  = aws_s3_bucket.acpet1-mediabucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

#create s3 code bucket
resource "aws_s3_bucket" "acpet1-codebucket" {
  bucket = "acpet1-code-bucket"
  force_destroy = true
  tags = {
    Name        = "acpet1-code-bucket"
    Environment = "Dev"
  }
}
#public access not enabled
resource "aws_s3_bucket_public_access_block" "Private_access" {
  bucket                  = aws_s3_bucket.acpet1-codebucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#create bucket policy
resource "aws_s3_bucket_policy" "acpet1-mediabucketpolicy" {
  bucket = aws_s3_bucket.acpet1-mediabucket.id
  policy = jsonencode({
    Id = "acpet1-mediabucketpolicy"
    Statement = [
      {
        Action = "s3:GetObject"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Resource = "arn:aws:s3:::acpet1-media-bucket/*"
        Sid      = "PublicReadGetObject"
      }
    ]
    Version = "2012-10-17"
  })
}
# create IAM role and policy
resource "aws_iam_role" "acpet1_iam_role" {
  name        = "acpet1_iam_role"
  description = "S3 Full Permission"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    tag-key = "acpet1_iam_profile"
  }
}
# create s3 bucket for media logs
resource "aws_s3_bucket" "acpet1-medialogsbucket" {

  bucket = "acpet1-medialogs-bucket"

  #acl           = "public-read"

  force_destroy = true

  tags = {

    Name = "acpet1-medialogs-bucket"

  }

}

#Update bucket policy for MEDIA Logs

resource "aws_s3_bucket_policy" "acpet1-medialogsbucket" {

  bucket = aws_s3_bucket.acpet1-mediabucket.id

  policy = jsonencode({

    Id = "mediaBucketlogsPolicy"

    Statement = [

      {

        Action = "s3:GetObject"

        Effect = "Allow"

        Principal = {

          AWS = "*"

        }

        Resource = "arn:aws:s3:::acpet1-media-bucket/*"

        Sid = "PublicReadGetObject"

      }

    ]

    Version = "2012-10-17"

  })

}

# Create Database Subnet Group
resource "aws_db_subnet_group" "acpet1_db_subnet_group" {
  name       = "acpet1_db_subnet_group"
  subnet_ids = [aws_subnet.acpet1_prvsn_01.id, aws_subnet.acpet1_prvsn_02.id]
  tags = {
    Name = "acpet1_db_subnet_group"
  }
}
#Create MySQL RDS Instance
resource "aws_db_instance" "acpet1_rds" {
  identifier = "acpet1database"
  allocated_storage = 20
  engine = "mysql"
  engine_version = "8.0"
  instance_class = "db.t2.micro"
  port = "3306"
  db_name = "acpet1db"
  username = var.db_username
  password = var.db_password
  multi_az               = true
  parameter_group_name   = "default.mysql8.0"
  deletion_protection    = false
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.acpet1_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.acpet1_backend_sg.id]
}

data "aws_cloudfront_distribution" "acpet1-distribution" {
 id= "${aws_cloudfront_distribution.acpet1-distribution.id}"
}

 # Create Cloudfront disitribution
locals {
  s3_origin_id = "aws_s3_bucket.acpet1-mediabucket.id"
}
resource "aws_cloudfront_distribution" "acpet1-distribution" {
  enabled             = true
  origin {
    domain_name = aws_s3_bucket.acpet1-mediabucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
  }
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 300
  }
   price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# Create a keypair

resource "aws_key_pair" "acpet1-key" {
  key_name   = "variable.acpet1-key"
  public_key = file(var.acpet1-key) 

}

# Create the EC2 Instance
resource "aws_instance" "acpet1_ec2" {
  ami                         = var.ami
  instance_type               = "t2.micro"
  vpc_security_group_ids      = [aws_security_group.acpet1_frontend_sg.id]
  subnet_id                   = aws_subnet.acpet1_pubsn_01.id
  key_name                    = "variable.acpet1-key"
  iam_instance_profile        = aws_iam_instance_profile.acpet1-IAM-Profile.id
  associate_public_ip_address = true
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo yum install unzip -y
unzip awscliv2.zip
sudo ./aws/install
sudo yum install httpd php php-mysqlnd -y
cd /var/www/html
touch indextest.html
echo "This is a test file" > indextest.html
sudo yum install wget -y
wget https://wordpress.org/wordpress-5.1.1.tar.gz
tar -xzf wordpress-5.1.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress
rm -rf wordpress-5.1.1.tar.gz
chmod -R 755 wp-content
chown -R apache:apache wp-content
wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
mv htaccess.txt .htaccess
cd /var/www/html && mv wp-config-sample.php wp-config.php
sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', 'acpet1db' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', 'admin' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', 'EuTeam1password' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define('DB_HOST','acpet1database.chrirzobdcnc.eu-west-2.rds.amazonaws.com')@g" /var/www/html/wp-config.php
cat <<EOT> /etc/httpd/conf/httpd.conf
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
<Directory />
    AllowOverride none
    Require all denied
</Directory>
DocumentRoot "/var/www/html"
<Directory "/var/www">
    AllowOverride None
    # Allow open access:
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>
<Files ".ht*">
    Require all denied
</Files>
ErrorLog "logs/error_log"
LogLevel warn
<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    <IfModule logio_module>
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\" %I %O" combinedio
    </IfModule>
    CustomLog "logs/access_log" combined
</IfModule>
<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>
AddDefaultCharset UTF-8
<IfModule mime_magic_module>
        MIMEMagicFile conf/magic
</IfModule>
EnableSendfile on
IncludeOptional conf.d/*.conf
EOT
cat <<EOT> /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
rewriterule ^wp-content/uploads/(.*)$ http://${data.aws_cloudfront_distribution.acpet1-distribution.domain_name}/\$1 [r=301,nc]
# BEGIN WordPress
# END WordPress
EOT
aws s3 cp --recursive /var/www/html/ s3://acpet1-code-bucket
aws s3 sync /var/www/html/ s3://acpet1-code-bucket
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete s3://acpet1-code-bucket /var/www/html/" > /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://acpet1-mediabucket" >> /etc/crontab
sudo chkconfig httpd on
sudo service httpd start
sudo setenforce 0
  EOF
  tags = {
    Name = "acpet1"
  }
}

#Create IAM role for EC2
resource "aws_iam_instance_profile" "acpet1-IAM-Profile" {
  name = "acpet1-IAM-Profile"
  role = aws_iam_role.acpet1-IAM-Role.name
}
resource "aws_iam_role" "acpet1-IAM-Role" {
  name        = "acpet1-IAM-Role"
  description = "S3 Full Permission"

 

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    tag-key = "acpet1-IAM-Profile"
  }
}
#IAM role Policy attachment
resource "aws_iam_role_policy_attachment" "acpet1-role-pol-attach" {
  role       = aws_iam_role.acpet1-IAM-Role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}


#Add an Application Load Balancer
# resource "aws_lb" "acpet1-alb" {
#   name                       = "acpet1-alb"
#   internal                   = false
#   load_balancer_type         = "application"
#   security_groups            = [aws_security_group.acpet1_frontend_sg.id]
#   subnets                    = [aws_subnet.acpet1_pubsn_01.id, aws_subnet.acpet1_pubsn_02.id]
#   enable_deletion_protection = false
#   access_logs {
#     bucket = "aws_s3_bucket.acpet1-mediabucket"
#     prefix = "acpet1"
#   }
# }

# # Create a Target Group for Load Balancer
# resource "aws_lb_target_group" "acpet1-tg" {
#   name     = "acpet1-tg"
#   port     = 80
#   protocol = "HTTP"
#   vpc_id   = aws_vpc.acpet1_vpc.id
#   health_check {
#     healthy_threshold   = 3
#     unhealthy_threshold = 10
#     interval            = 90
#     timeout             = 60
#     path                = "/indextest.html"
#   }
# }


# #Add a load balancer Listener
# resource "aws_lb_listener" "acpet1-lb-listener" {
#   load_balancer_arn = aws_lb.acpet1-alb.arn
#   port              = "80"
#   protocol          = "HTTP"

 

#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.acpet1-tg.arn
#   }
# }

# #Create AMI from EC2 Instance
# resource "aws_ami_from_instance" "acpet1_ami" {
#   name               = "acpet1_ami"
#   source_instance_id = aws_instance.acpet1_ec2.id
# }
# #Create Launch Configuration
# resource "aws_launch_configuration" "acpet1_lc" {
#   name_prefix                 = "acpet1-lc-"
#   image_id                    = aws_ami_from_instance.acpet1_ami.id
#   instance_type               = "t2.micro"
#   iam_instance_profile        = aws_iam_instance_profile.acpet1-IAM-Profile.id
#   associate_public_ip_address = true
#   security_groups             = ["${aws_security_group.acpet1_frontend_sg.id}"]
#   key_name                    = aws_key_pair.acpet1-key.key_name
#   lifecycle {
#     create_before_destroy = true
#   }
# }
# #Create Auto Scaling group
# resource "aws_autoscaling_group" "acpet1_asg" {
#   name                 = "acpet1-new-ASG"
#   launch_configuration = aws_launch_configuration.acpet1_lc.name
#   #Defines the vpc, az and subnets to launch in
#   vpc_zone_identifier       = ["${aws_subnet.acpet1_pubsn_01.id}", "${aws_subnet.acpet1_pubsn_02.id}"]
#   target_group_arns         = ["${aws_lb_target_group.acpet1-tg.arn}"]
#   health_check_type         = "EC2"
#   health_check_grace_period = 30
#   desired_capacity          = 2
#   max_size                  = 4
#   min_size                  = 2
#   force_delete              = true
#   lifecycle {
#     create_before_destroy = true
#   }
# }
# resource "aws_autoscaling_policy" "acpet1_asg_policy" {
#   name                   = "acpet1_asg_policy"
#   policy_type            = "TargetTrackingScaling"
#   adjustment_type        = "ChangeInCapacity"
#   autoscaling_group_name = aws_autoscaling_group.acpet1_asg.name
#   target_tracking_configuration {
#     predefined_metric_specification {
#       predefined_metric_type = "ASGAverageCPUUtilization"
#     }
#     target_value = 60.0
#   }
# }
# # Creating Route 53 Custom Domain
# resource "aws_route53_zone" "acpet1_hosted_zone" {
#     name = "barbarachiragia.com"
#     tags = {
#     Environment = "dev"
#   }
# }
# #Create A record
# resource "aws_route53_record" "www" {
#   zone_id = aws_route53_zone.acpet1_hosted_zone.zone_id
#   name    = "oladapoiyanda.com"
#   type    = "A"
#   ttl     = 300
#   records = ["${aws_instance.acpet1_ec2_instance.public_ip}"]
# }