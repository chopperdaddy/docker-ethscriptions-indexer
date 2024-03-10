class ConsensusController < ApplicationController
  def index
    # Assuming Ethscription is your model and it responds to the mentioned attributes
    ethscriptions = Ethscription.select(:transaction_hash, :previous_owner, :current_owner, :sha, :creator)
    
    render json: ethscriptions
  end
end
