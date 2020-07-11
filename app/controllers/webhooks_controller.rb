class WebhooksController < ApplicationController

  skip_before_action :verify_authenticity_token

  def inbound
    topic = request.headers['X-Shopify-Topic']
    shop_domain = request.headers['X-Shopify-Shop-Domain']
    request_sha = request.headers['HTTP_X_SHOPIFY_HMAC_SHA256']

    data = request.body.read

    head :ok and return unless verify_webhook(data, request_sha)

    shop = Shop.find_by(shopify_domain: shop_domain)

    if topic == 'customers/redact'
      puts "customer redact"
    elsif topic == 'shop/redact'
      puts "shop redact"
    elsif topic == 'customers/data_request'
      puts "data request"
    elsif topic == "checkouts/update"
      #do something with that checkout
    else
      puts "Unrecognized topic - #{topic} for #{shop_domain}"
    end

    head :ok and return
  end
end


private

def verify_webhook(data, hmac_header)
	calculated_hmac = Base64.strict_encode64(OpenSSL::HMAC.digest('sha256', ENV['SHOPIFY_SECRET'], data))
	ActiveSupport::SecurityUtils.secure_compare(calculated_hmac, hmac_header)
end
