class ConsensusController < ApplicationController
  # Basic pagination method for simplicity
  # Adjust according to your application's pagination needs
  def paginate(query)
    per_page = params.fetch(:per_page, 10).to_i
    page = params.fetch(:page, 1).to_i
    offset = (page - 1) * per_page

    total_count = query.count
    records = query.limit(per_page).offset(offset)

    [records, { total_count: total_count, page: page, per_page: per_page }]
  end

  def index
    ethscriptions_scope = Ethscription.select(:transaction_hash, :previous_owner, :current_owner, :creator)
    
    # Basic pagination
    ethscriptions, pagination_info = paginate(ethscriptions_scope)

    render json: { 
      ethscriptions: ethscriptions.as_json,
      pagination: pagination_info
    }
  end
end
