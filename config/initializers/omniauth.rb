Rails.application.config.middleware.use OmniAuth::Builder do
  provider :facebook, ENV['FACEBOOK_CLIENT_ID'],  ENV['FACEBOOK_CLIENT_SECRET'], provider_ignores_state: true
  provider :bigcommerce, ENV['BC_CLIENT_ID'], ENV['BC_CLIENT_SECRET'],
  {
    scope: "store_v2_products",
    client_options: {
      site: 'https://login.bigcommerce.com'
    }
  }
end
