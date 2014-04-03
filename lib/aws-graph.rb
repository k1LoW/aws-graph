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
      ec2_instances = @ec2.instances # EC2 instances
      vpcs = @ec2.vpcs # VPC Collection
      security_groups = @ec2.security_groups # EC2 security groups
      rds_client = @rds.client # RDS low level client
      db_instances = rds_client.describe_db_instances
      db_security_groups = rds_client.describe_db_security_groups
      lbs = @elb.load_balancers # ELB

      secret = options[:secret]

      @formated = {}
      sg_hash = {}
      lb_sg = nil

      # Create EC2 security group cluster
      @formated[:security_groups] = {}
      security_groups.each do | sg |
        cluster_id = 'cluster' + sg.id.gsub(/[-\/]/,'')
        sg_hash[sg.id] = cluster_id
        
        if sg.vpc_id
          print "v"
          label = sg.name + '[' + sg.id + ']' + '[vpc]'
        else
          print "."
          label = sg.name + '[' + sg.id + ']'
        end
      
        @formated[:security_groups][sg.id.to_sym] = {
          label: label,
          vpc_id: sg.vpc_id,
          instances: {},
          inbounds: {},
        }
      end

      # Create RDS security group cluster
      db_security_groups[:db_security_groups].each do | db_sg |
        print "."
        if db_sg[:vpc_id]
          print "v"
          label = db_sg[:db_security_group_name] + '[vpc]'
        else
          print "."
          label = db_sg[:db_security_group_name]
        end
        @formated[:security_groups][db_sg[:db_security_group_name].to_sym] = {
          label: label,
          vpc_id: db_sg[:vpc_id],
          instances: {},
          inbounds: {},
        }
      end

      # Append EC2 to EC2 security group
      ec2_instances.each do | e |
        e.security_groups.each do | sg |
          print "."
          label = '[' + e.id + ']'
          e.tags.each do | t |
            label = t[1] + '[' + e.id + ']' if t[0] == 'Name'
          end
          @formated[:security_groups][sg.id.to_sym][:instances][e.id.to_sym] = {
              label: label,
              type: :ec2,
              status: e.status,              
          }
        end
      end

      # Append VPC EC2 to EC2 security group
      vpcs.each do | vpc |
        vpc.instances.each do | e |
          e.security_groups.each do | sg |
            print "v"
            label = '[' + e.id + ']'
            e.tags.each do | t |
              label = t[1] + '[' + e.id + ']' if t[0] == 'Name'
            end
            @formated[:security_groups][sg.id.to_sym][:instances][e.id.to_sym] = {
              label: label,
              type: :ec2,
              status: e.status,              
            }
          end
        end
      end

      # Append RDS to RDS security group
      db_instances[:db_instances].each do | r |
        r[:db_security_groups].each do | db_sg |
          print "."
          @formated[:security_groups][db_sg[:db_security_group_name].to_sym][:instances][r[:db_instance_identifier].to_sym] = {
            label: Util.new.label(r[:db_instance_identifier], secret),
            type: :rds,
            status: r[:db_instance_status],
          }
        end
        r[:vpc_security_groups].each do | sg |
          print "v"
          @formated[:security_groups][sg[:vpc_security_group_id].to_sym][:instances][r[:db_instance_identifier].to_sym] = {
            label: Util.new.label(r[:db_instance_identifier], secret),
            type: :rds,
            status: r[:db_instance_status],
          }
        end
      end

      # Add edges EC2 security group
      security_groups.each do | sg |
        ips = sg.ingress_ip_permissions # inbound permissions
        ips.each do | ip |
          # CDIR
          ip.ip_ranges.each do | r |
            unless @formated[:security_groups][sg.id.to_sym][:inbounds].has_key?(r.to_sym)
              @formated[:security_groups][sg.id.to_sym][:inbounds][r.to_sym] = []
            end
            @formated[:security_groups][sg.id.to_sym][:inbounds][r.to_sym].push({
              port_range: ip.port_range,
              protocol: ip.protocol,
            })
          end

          # EC2 security group -> EC2 security group instances
          ip.groups.each do | fromsg |
            next if fromsg.id == sg.id
            print "-"
            unless sg_hash[fromsg.id]
              # Unknown security group is amazon-elb/amazon-elb-sg
              lb_sg = fromsg.id.to_sym
              @formated[:security_groups][fromsg.id.to_sym] = {
                label: 'amazon-elb/amazon-elb-sg',
                instances: {},
                inbounds: {},
              }
            end
            unless @formated[:security_groups][sg.id.to_sym][:inbounds].has_key?(fromsg.id.to_sym)
              @formated[:security_groups][sg.id.to_sym][:inbounds][fromsg.id.to_sym] = []
            end
            @formated[:security_groups][sg.id.to_sym][:inbounds][fromsg.id.to_sym].push({
              port_range: ip.port_range,
              protocol: ip.protocol,
            })
            # route from_cluster_id.to_sym => to_cluster_id.to_sym
            # edge (from_cluster_id + '_' + to_cluster_id).to_sym, color: '#005580', headlabel: Util.new.label(Util.new.ip_range(ip.port_range.to_s) + '[' + ip.protocol.to_s + ']', secret), fontcolor: '#005580'
          end
        end
      end

      # EC2 security group -> RDS security group
      db_security_groups[:db_security_groups].each do | db_sg |
        print "-"
        db_sg[:ec2_security_groups].each do | sg |
          if sg[:ec2_security_group_id]
            unless @formated[:security_groups][db_sg[:db_security_group_name].to_sym][:inbounds].has_key?(sg[:ec2_security_group_id].to_sym)
              @formated[:security_groups][db_sg[:db_security_group_name].to_sym][:inbounds][sg[:ec2_security_group_id].to_sym] = []
            end
            @formated[:security_groups][db_sg[:db_security_group_name].to_sym][:inbounds][sg[:ec2_security_group_id].to_sym].push({
              port_range: 'RDS',
              protocol: nil,
            })
          else
            # なぜかdb_security_group_idが存在しないものがある
            security_groups.each do | s |
              if s.name == sg[:ec2_security_group_name]
                unless @formated[:security_groups][db_sg[:db_security_group_name].to_sym][:inbounds].has_key?(s.id.to_sym)
                  @formated[:security_groups][db_sg[:db_security_group_name].to_sym][:inbounds][s.id.to_sym] = []
                end
                @formated[:security_groups][db_sg[:db_security_group_name].to_sym][:inbounds][s.id.to_sym].push({
                  port_range: 'RDS',
                  protocol: nil,
                })
              end
            end
          end
        end
      end

      # Append ELB to ELB security group
      lbs.each do | lb |
        break unless lb_sg
        @formated[:security_groups][lb_sg][:instances][lb.name.to_sym] = {
          label: lb.name,
          type: :elb,
          status: nil,
        }
      end

      puts ''
      filename = File.basename options[:output], ".*"
      dirpath = File.dirname options[:output]
      fileextname = File.extname options[:output]
      fileformat = fileextname.sub('.', '').to_sym
      case fileformat
        when :dot
        self.save_png File.join(dirpath, filename)
        File.delete(File.join(dirpath, filename + '.png'))
        when :png
        self.save_png File.join(dirpath, filename)
        File.delete(File.join(dirpath, filename + '.dot'))
      else

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

    protected
    def save_png(filepath)
      secret = options[:secret]
      f = @formated

      gv = Gviz.new(:AWS, :digraph)
      gv.graph do
        global layout:'fdp', overlap:false, compound:true, rankdir:'LR'
        edges lhead: '', ltail: ''
        nodes shape: 'box'
        f[:security_groups].each do | sg_id, sg |
          cluster_id = 'cluster' + sg_id.to_s.gsub(/[-\/]/,'')
          if sg[:vpc_id]
            color = '#4B75B9'
            label = Util.new.label(sg[:label], secret)
            style = 'rounded,bold'
          else
            color = '#333333'
            label = Util.new.label(sg[:label], secret)
            style = 'rounded,bold'
          end
          subgraph(cluster_id.to_sym) do
            global label: label, style: style, color: color
            sg[:instances].each do | i_id, i |
              case i[:type]
              when :ec2
                if i[:status] == :running
                  image_path = File.dirname(__FILE__) + '/ec2.png'
                else
                  image_path = File.dirname(__FILE__) + '/ec2_disactive.png'
                end
              when :rds
                image_path = File.dirname(__FILE__) + '/rds.png'
              when :elb
                image_path = File.dirname(__FILE__) + '/elb.png'
              else
                image_path = File.dirname(__FILE__) + '/ec2_disactive.png'
              end
              node (sg_id.to_s + i_id.to_s).gsub(/[-\/]/, '').to_sym, label: i[:label], shape: :none, image: image_path
            end
            
            sg[:inbounds].each do | ip, inbounds |

              # Security Group -> Security Group
              if /\Asg\-/.match(ip.to_s)
                from_cluster_id = 'cluster' + ip.to_s.gsub(/[-\/]/,'')
                route from_cluster_id.to_sym => cluster_id.to_sym
                label = []
                inbounds.each do | inbound |
                  label.push(Util.new.format_range(inbound[:port_range].to_s) + '(' + inbound[:protocol].to_s + ')')
                end
                edge (from_cluster_id + '_' + cluster_id).to_sym, color: '#005580', headlabel: label.join(','), fontcolor: '#005580'
              end
            end
          end
        end
      end
      gv.save(filepath, :png)
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
    def format_range(ip_range)
      if ip_range.sub(/\A[0-9]+\.\./,'') == ip_range.sub(/\.\.[0-9]+\z/,'')
        return ip_range.sub(/\A[0-9]+\.\./,'')
      else
        return ip_range
      end
    end
  end
end
