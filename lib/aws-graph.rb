# -*- coding: utf-8 -*-
require "aws-graph/version"
require "thor"
require 'aws-sdk'
require 'gviz'

module AwsGraph
  class CLI < Thor

    desc "draw [config.yml]", "Draw AWS network graph"
    method_option :config, :type => :string, :aliases => '-c', :default => 'config.yml', :banner => 'AWS config.yml'
    method_option :output, :type => :string, :aliases => '-o', :default => 'output.png', :banner => 'output file path'
    method_option :secret, :type => :boolean, :aliases => '-s', :default => false, :banner => 'mask label'
    def draw()
      yml = options[:config]
      self.load(yml)
      self.sg()
    end

    protected
    def sg()
      gv = Gviz.new(:AWS, :digraph)

      ec2_instances = @ec2.instances # EC2 instances
      vpcs = @ec2.vpcs # VPC Collection
      security_groups = @ec2.security_groups # EC2 security groups
      rds_client = @rds.client # RDS low level client
      db_instances = rds_client.describe_db_instances
      db_security_groups = rds_client.describe_db_security_groups
      lbs = @elb.load_balancers # ELB

      secret = options[:secret]

      gv.graph do
        global layout:'fdp', overlap:false, compound:true, rankdir:'LR'
        edges lhead: '', ltail: ''
        nodes shape: 'box'

        sg_hash = {}

        # Create EC2 security group cluster
        security_groups.each do | sg |
          cluster_id = 'cluster' + sg.id.gsub(/[-\/]/,'')
          sg_hash[sg.id] = cluster_id
          
          if sg.vpc_id
            print "v"
            color = '#4B75B9'
            label = Util.new.label(sg.name + '[' + sg.id + ']', secret) + '[vpc]'
            style = 'rounded,bold'
          else
            print "."
            color = '#333333'
            label = Util.new.label(sg.name + '[' + sg.id + ']', secret)
            style = 'rounded,bold'
          end
          
          subgraph(cluster_id.to_sym) do
            global label: label, style: style, color: color
          end
        end

        # Create RDS security group cluster
        db_security_groups[:db_security_groups].each do | db_sg |
          print "."
          cluster_id = 'cluster' + db_sg[:db_security_group_name].gsub(/[-\/]/,'')
          if db_sg[:vpc_id]
            print "v"
            color = '#4B75B9'
            label = Util.new.label(db_sg[:db_security_group_name], secret) + '[vpc]'
            style = 'rounded,bold'
          else
            print "."
            color = '#333333'
            label = Util.new.label(db_sg[:db_security_group_name], secret)
            style = 'rounded,bold'
          end
          subgraph(cluster_id.to_sym) do
            global label: label, style: style, color: color
          end
        end

        # Append EC2 to EC2 security group
        ec2_instances.each do | e |
          if e.status == :running
            image_path = File.dirname(__FILE__) + '/ec2.png'
          else
            image_path = File.dirname(__FILE__) + '/ec2_disactive.png'
          end
          e.security_groups.each do | sg |
            print "."
            cluster_id = 'cluster' + sg.id.gsub(/[-\/]/,'')
            label = '[' + e.id + ']'
            e.tags.each do | t |
              label = t[1] + '\n' + '[' + e.id + ']' if t[0] == 'Name'
            end
            subgraph(cluster_id.to_sym) do
              node (sg.id + e.id).gsub(/[-\/]/, '').to_sym, label: Util.new.label(label, secret), shape: :none, image: image_path
            end
          end
        end

        # Append VPC EC2 to EC2 security group
        vpcs.each do | vpc |
          vpc.instances.each do | e |
            if e.status == :running
              image_path = File.dirname(__FILE__) + '/ec2.png'
            else
              image_path = File.dirname(__FILE__) + '/ec2_disactive.png'
            end
            e.security_groups.each do | sg |
              print "v"
              cluster_id = 'cluster' + sg.id.gsub(/[-\/]/,'')
              label = '[' + e.id + ']'
              e.tags.each do | t |
                label = t[1] + '\n' + '[' + e.id + ']' if t[0] == 'Name'
              end
              subgraph(cluster_id.to_sym) do
                node (sg.id + e.id).gsub(/[-\/]/, '').to_sym, label: Util.new.label(label, secret), shape: :none, image: image_path
              end
            end
          end
        end

        # Append RDS to RDS security group
        db_instances[:db_instances].each do | r |
          r[:db_security_groups].each do | db_sg |
            print "."
            cluster_id = 'cluster' + db_sg[:db_security_group_name].gsub(/[-\/]/,'')
            image_path = File.dirname(__FILE__) + '/rds.png'
            subgraph(cluster_id.to_sym) do
              node (r[:db_instance_identifier]).gsub(/[-\/]/, '').to_sym, label: Util.new.label(r[:db_instance_identifier], secret), shape: :none, image: image_path
            end
          end
          r[:vpc_security_groups].each do | sg |
            print "v"
            cluster_id = 'cluster' + sg[:vpc_security_group_id].gsub(/[-\/]/,'')
            image_path = File.dirname(__FILE__) + '/rds.png'
            subgraph(cluster_id.to_sym) do
              node (r[:db_instance_identifier]).gsub(/[-\/]/, '').to_sym, label: Util.new.label(r[:db_instance_identifier], secret), shape: :none, image: image_path
            end
          end
        end

        # Add edges EC2 security group
        security_groups.each do | sg |
          ips = sg.ingress_ip_permissions # inbound permissions
          ips.each do | ip |

            # EC2 security group -> EC2 security group
            ip.groups.each do | fromsg |
              next if fromsg.id == sg.id
              print "-"
              unless sg_hash[fromsg.id]
                # Unknown security group is amazon-elb/amazon-elb-sg
                cluster_id = 'cluster' + fromsg.id.gsub(/[-\/]/,'')
                sg_hash['amazon-elb/amazon-elb-sg'] = cluster_id
                subgraph(cluster_id.to_sym) do
                  global label: Util.new.label('amazon-elb/amazon-elb-sg', false), style: 'rounded'
                end
              end
              from_cluster_id = 'cluster' + fromsg.id.gsub(/[-\/]/,'')
              to_cluster_id = 'cluster' + sg.id.gsub(/[-\/]/,'')
              route from_cluster_id.to_sym => to_cluster_id.to_sym
              edge (from_cluster_id + '_' + to_cluster_id).to_sym, label: Util.new.label(Util.new.ip_range(ip.port_range.to_s) + '[' + ip.protocol.to_s + ']', secret)
            end
          end
        end

        # EC2 security group -> RDS security group
        db_security_groups[:db_security_groups].each do | db_sg |
          print "-"
          db_sg[:ec2_security_groups].each do | sg |
            if sg[:ec2_security_group_id]
              from_cluster_id = 'cluster' + sg[:ec2_security_group_id].gsub(/[-\/]/,'')
              to_cluster_id = 'cluster' + db_sg[:db_security_group_name].gsub(/[-\/]/,'')
              route from_cluster_id.to_sym => to_cluster_id.to_sym
              edge (from_cluster_id + '_' + to_cluster_id).to_sym, label: 'RDS'
            else
              # なぜかdb_security_group_idが存在しないものがある
              security_groups.each do | s |
                if s.name == sg[:ec2_security_group_name]
                  from_cluster_id = 'cluster' + s.id.gsub(/[-\/]/,'')
                  to_cluster_id = 'cluster' + db_sg[:db_security_group_name].gsub(/[-\/]/,'')
                  route from_cluster_id.to_sym => to_cluster_id.to_sym
                  edge (from_cluster_id + '_' + to_cluster_id).to_sym, label: 'RDS'
                end
              end
            end
          end
        end

        # Append ELB to ELB security group
        lbs.each do | lb |
          break unless sg_hash['amazon-elb/amazon-elb-sg']
          cluster_id = sg_hash['amazon-elb/amazon-elb-sg']
          image_path = File.dirname(__FILE__) + '/elb.png'
          subgraph(cluster_id.to_sym) do
            node lb.name.gsub('-', '').to_sym, label: Util.new.label(lb.name, secret), shape: :none, image: image_path
          end
        end

        puts ''
      end
      filename = File.basename options[:output], ".*"
      filepath = File.dirname options[:output]
      fileextname = File.extname options[:output]
      fileformat = fileextname.sub('.', '').to_sym
      unless fileformat == :dot
        gv.save(File.join(filepath, filename), fileformat)
        File.delete(File.join(filepath, "#{filename}.dot"))
      else
        gv.save(File.join(filepath, filename), :png)
        File.delete(File.join(filepath, "#{filename}.png"))
      end
    end

    protected
    def load(yml)
      @config = YAML.load_file(yml)
      @ec2 = AWS::EC2.new(
                          :access_key_id => @config['aws_access_key_id'],
                          :secret_access_key => @config['aws_secret_access_key'],
                          :region => @config['aws_region'],
                          )
      @rds = AWS::RDS.new(
                          :access_key_id => @config['aws_access_key_id'],
                          :secret_access_key => @config['aws_secret_access_key'],
                          :region => @config['aws_region'],
                          )
      @elb = AWS::ELB.new(
                          :access_key_id => @config['aws_access_key_id'],
                          :secret_access_key => @config['aws_secret_access_key'],
                          :region => @config['aws_region'],
                          )
    end
  end

  class Util
    def label(text, secret)
      if secret
        return text.gsub(/[^\[\]]/,'*')
      else
        return text
      end
    end
    def ip_range(ip_range)
      if ip_range.sub(/\A[0-9]+\.\./,'') == ip_range.sub(/\.\.[0-9]+\z/,'')
        return ip_range.sub(/\A[0-9]+\.\./,'')
      else
        return ip_range
      end
    end
  end
end
