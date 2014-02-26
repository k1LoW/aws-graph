# aws-graph

Draw AWS network graph

![sample](http://github.com/k1LoW/aws-graph/raw/master/sample.png)

## Installation

Add this line to your application's Gemfile:

    gem 'aws-graph'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install aws-graph

## Usage

Make config.yml

    aws_access_key_id: XXXXXXXXXXXXXXXXXXXX
    aws_secret_access_key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    aws_region: ap-northeast-1

And draw graph

    $ aws-graph draw -c config.yml -o output.png

## Contributing

1. Fork it ( http://github.com/<my-github-username>/aws-graph/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
