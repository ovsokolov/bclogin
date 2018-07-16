Rails.application.routes.draw do
  root 'welcome#index'
  get '/auth/:name/callback' => 'omniauths#callback'
  get '/load' => 'omniauths#load'
  get '/uninstall' => 'omniauths#uninstall'
  get '/get_login' => 'omniauths#get_login'
  get '/auth/:provider/callback', :to => 'omniauths#create'
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
end
