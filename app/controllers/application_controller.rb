class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  after_filter :set_header_for_iframe

  def set_header_for_iframe
    response.headers.delete('X-Frame-Options')
  end
end
