require "aws-graph/version"
require "thor"
require 'aws-sdk'
require 'graphviz'
require 'pp'

module AwsGraph
  class CLI < Thor

    desc "draw [config.yml]", "Draw AWS network graph"
    method_option :config, :type => :string, :aliases => '-c', :default => 'config.yml', :banner => 'AWS config.yml'
    method_option :output, :type => :string, :aliases => '-o', :default => 'output.png', :banner => 'output file path'
    method_option :secret, :type => :boolean, :aliases => '-s', :default => false, :banner => 'mask label'
    def draw()
      @secret = options[:secret]
      yml = options[:config]
      self.load(yml)
      self.sg()
    end

    protected
    def sg()
      g = GraphViz::new( "G",
                         :type => :digraph,
                         :use => :fdp,
                         :layout => :fdp,
                         :overlap => false,
                         :compound => true,
                         :rankdir => 'LR'
                         )
      g.edge["lhead"] = ""
      g.edge["ltail"] = ""
      g.node[:shape] = 'box'
      ec2_instances = @ec2.instances # EC2 instances
      vpcs = @ec2.vpcs # VPC Collection
      security_groups = @ec2.security_groups # EC2 security groups
      rds_client = @rds.client # RDS low level client
      db_instances = rds_client.describe_db_instances
      db_security_groups = rds_client.describe_db_security_groups
      lbs = @elb.load_balancers # ELB

      sg_hash = {}

      # Create EC2 security group cluster
      security_groups.each do | sg |
        print "."
        sg_hash[sg.id] = g.add_graph('cluster' + sg.id,
                                  :label => self.label(sg.name + '[' + sg.id + ']'),
                                  :style => 'rounded')
      end

      # Create RDS security group cluster
      db_security_groups[:db_security_groups].each do | db_sg |
        print "."
        sg_hash[db_sg[:db_security_group_name]] = g.add_graph('cluster' + db_sg[:db_security_group_name],
                                                           :label => self.label(db_sg[:db_security_group_name]),
                                                           :style => 'rounded')
      end

      # Append EC2 to EC2 security group
      ec2a = {}
      ec2_instances.each do | e |
        if e.status == :running
          image_path = File.dirname(__FILE__) + '/ec2.png'
        else
          image_path = File.dirname(__FILE__) + '/ec2_disactive.png'
        end
        e.security_groups.each do | sg |
          print "."
          ec2a[e.id] = sg_hash[sg.id].add_nodes(sg.id + '-' + e.id, :label => self.label(e.id),
                                             :shape => :none,
                                             :image => image_path)
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
            ec2a[e.id] = sg_hash[sg.id].add_nodes(sg.id + '-' + e.id, :label => self.label(e.id),
                                               :shape => :none,
                                               :image => image_path)
          end
        end
      end

      # Append RDS to RDS security group
      db_instancesa = {}
      db_instances[:db_instances].each do | r |
        r[:db_security_groups].each do | sg |
          print "."
          ec2a[r[:db_instance_identifier]] = sg_hash[sg[:db_security_group_name]].add_nodes(r[:db_instance_identifier], :label => self.label(r[:db_instance_identifier]), :shape => :none, :image => File.dirname(__FILE__) + '/rds.png')
        end
        r[:vpc_security_groups].each do | sg |
          print "v"
          ec2a[r[:db_instance_identifier]] = sg_hash[sg[:vpc_security_group_id]].add_nodes(r[:db_instance_identifier], :label => self.label(r[:db_instance_identifier]), :shape => :none, :image => File.dirname(__FILE__) + '/rds.png')
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
              unknown = AWS::EC2::SecurityGroup.new(fromsg.id)
              # Unknown security group is amazon-elb/amazon-elb-sg
              sg_hash['amazon-elb/amazon-elb-sg'] = g.add_graph('cluster' + fromsg.id,
                                                             :label => 'amazon-elb/amazon-elb-sg',
                                                             :style => 'rounded')
            end
            g.add_edge('cluster' + fromsg.id,
                       'cluster' + sg.id,
                       :label => self.label(ip.port_range.to_s + '[' + ip.protocol.to_s + ']'))
          end
        end
      end

      # EC2 security group -> RDS security group
      db_security_groups[:db_security_groups].each do | db_sg |
        print "-"
        db_sg[:ec2_security_groups].each do | sg |
          if sg[:ec2_security_group_id]
            g.add_edge('cluster' + sg[:ec2_security_group_id],
                       'cluster' + db_sg[:db_security_group_name],
                       :label => 'RDS')
          else
            # なぜかdb_security_group_idが存在しないものがある
            security_groups.each do | s |
              g.add_edge('cluster' + s.id,
                       'cluster' + db_sg[:db_security_group_name],
                       :label => 'RDS') if s.name == sg[:ec2_security_group_name]
            end
          end
        end
      end

      # Append ELB to ELB security group
      lbs.each do | lb |
        break unless sg_hash['amazon-elb/amazon-elb-sg']
        sg_hash['amazon-elb/amazon-elb-sg'].add_nodes(lb.name, :label => self.label(lb.name), :shape => :none, :image => File.dirname(__FILE__) + '/elb.png')
      end

      # Empty security group
      sg_hash.each do | (key, sg) |
        next if sg.node_count > 0
        sg_hash[key].add_nodes(key + 'empty',
                            :label => 'empty',
                            :shape => :none,
                            )
      end

      g.output( :png => options[:output])

      puts ''
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
    def label(text)
      if @secret
        return '*****'
      else
        return text
      end
    end
  end
end
