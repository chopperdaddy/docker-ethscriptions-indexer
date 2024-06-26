require 'httparty'
require 'retryable'

class UniversalClient
  attr_accessor :base_url, :api_key

  def initialize(base_url: ENV['ETHEREUM_CLIENT_BASE_URL'], api_key: nil)
    self.base_url = base_url.chomp('/')
    self.api_key = api_key
  end

  def headers
    {
      'Accept' => 'application/json',
      'Content-Type' => 'application/json'
    }
  end

  def query_api(method:, params: [], timeout: 5, retries: 3)
    data = {
      id: 1,
      jsonrpc: '2.0',
      method: method,
      params: params
    }
    url = [base_url, api_key].join('/')

    Retryable.retryable(tries: retries, on: [Net::OpenTimeout, HTTParty::Error, Errno::ECONNREFUSED]) do
      HTTParty.post(url, body: data.to_json, headers: headers, timeout: timeout).parsed_response
    end
  end

  def get_block(block_number)
    query_api(
      method: 'eth_getBlockByNumber',
      params: ['0x' + block_number.to_s(16), true]
    )
  end

  def get_transaction_receipt(transaction_hash)
    query_api(
      method: 'eth_getTransactionReceipt',
      params: [transaction_hash]
    )
  end

  def get_transaction_receipts(block_number, blocks_behind: nil)
    receipts = query_api(
      method: 'eth_getBlockReceipts',
      params: ["0x" + block_number.to_s(16)]
    )['result']

    {
      'id' => 1,
      'jsonrpc' => '2.0',
      'result' => {
        'receipts' => receipts
      }
    }
  end

  def get_block_number
    query_api(method: 'eth_blockNumber')['result'].to_i(16)
  end
end
