class ConsensusController < ApplicationController
  def index
    scope = Ethscription.select(:id, :transaction_hash, :current_owner, :creator, :previous_owner)

    transaction_hashes = parse_param_array(params[:transaction_hashes])
    
    # Filter by transaction_hash if the parameter is present and is an array
    if params[:transaction_hashes].present?
      scope = scope.where(transaction_hash: transaction_hashes)
    end
    
    cache_on_block do
      results, pagination_response = paginate(scope)
      
      render json: {
        result: numbers_to_strings(results),
        pagination: pagination_response
      }
    end
  end
end
