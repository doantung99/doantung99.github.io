//SPDX-License-Identifier: MIT

pragma solidity 0.7.0;

contract StakingPool {
    uint32 private constant ONE_YEAR_IN_SECONDS = 365 days;

    address public owner;
    LinearPoolInfo[] public linearPoolInfo;
    mapping(uint256 => mapping(address => LinearStakingData)) public linearStakingData;
    mapping(address => uint[]) public linearPoolByAddress;

    modifier onlyOwner() {
        require(owner == msg.sender, "caller is not the owner");
        _;
    }

    event LinearDeposit(
        uint256 indexed poolId,
        address indexed account,
        uint256 amount
    );
    event LinearWithdraw(
        uint256 indexed poolId,
        address indexed account,
        uint256 amount
    );
    event LinearClaimReward(
        uint256 indexed poolId,
        address indexed account,
        uint256 amount
    );

    struct LinearPoolInfo {
        uint256 totalStaked;
        uint128 lockDuration;
        uint64 APR;
    }
    struct LinearStakingData {
        uint256 balance;
        uint256 reward;
        uint128 updatedTime;
        uint128 poolId;
    }

    constructor() public{
        owner = msg.sender;
    }    

    fallback() external payable{

    }

    function linearAddPool(
        uint128 _lockDuration,
        uint64 _APR
    ) external onlyOwner{
        linearPoolInfo.push(
            LinearPoolInfo({
                totalStaked: 0,
                lockDuration: _lockDuration,
                APR: _APR
            })
        );        
    }

    function linearDeposit(uint _poolId, uint _amount) external payable {
        address account = msg.sender;

        LinearPoolInfo storage pool = linearPoolInfo[_poolId];
        LinearStakingData storage stakingData = linearStakingData[_poolId][account];

        if (stakingData.balance == 0)
            linearPoolByAddress[account].push(_poolId);

        _linearHarvest(_poolId, account);

        require(_amount == msg.value, "linearDeposit: invalid deposit amount");

        stakingData.balance += _amount;
        stakingData.updatedTime = uint128(block.timestamp);
        stakingData.poolId = uint128(_poolId);
        pool.totalStaked += _amount;

        emit LinearDeposit(_poolId, account, _amount);
    }

    function linearWithdraw(uint256 _poolId, uint256 _amount) external{
        address account = msg.sender;

        LinearPoolInfo storage pool = linearPoolInfo[_poolId];
        LinearStakingData storage stakingData = linearStakingData[_poolId][account];

        require(block.timestamp - stakingData.updatedTime >= pool.lockDuration, "LinearWithdraw: still locked");

        linearClaimReward(_poolId);

        require(stakingData.balance >= _amount, "LinearWithdraw: invalid withdraw amount");

        msg.sender.call{value: _amount}("");
        stakingData.balance -= _amount;
        pool.totalStaked -= _amount;

        emit LinearWithdraw(_poolId, account, _amount);
    }

    function linearClaimReward(uint256 _poolId) public {
        address account = msg.sender;

        LinearPoolInfo storage pool = linearPoolInfo[_poolId];
        LinearStakingData storage stakingData = linearStakingData[_poolId][account];

        _linearHarvest(_poolId, account);
        if (stakingData.reward > 0) {
            msg.sender.call{value: stakingData.reward}("");
            emit LinearClaimReward(_poolId, account, stakingData.reward);
            stakingData.reward = 0;            
        }
    }

    function linearPendingReward(uint256 _poolId, address _account) public view returns (uint256 reward) {
        LinearPoolInfo storage pool = linearPoolInfo[_poolId];
        LinearStakingData storage stakingData = linearStakingData[_poolId][_account];

        uint128 startTime = stakingData.updatedTime > 0
            ? stakingData.updatedTime
            : uint128(block.timestamp);

        uint128 endTime = uint128(block.timestamp);
        if (
            pool.lockDuration > 0 &&
            stakingData.updatedTime + pool.lockDuration < block.timestamp
        ) {
            endTime = stakingData.updatedTime + pool.lockDuration;
        }

        uint128 stakedTimeInSeconds = endTime > startTime
            ? endTime - startTime
            : 0;
        uint256 pendingReward = ((stakingData.balance *
            stakedTimeInSeconds *
            pool.APR) / ONE_YEAR_IN_SECONDS) / 100;

        reward = stakingData.reward + pendingReward;
    }

    function _linearHarvest(uint256 _poolId, address _account) private {
        LinearStakingData storage stakingData = linearStakingData[_poolId][_account];

        stakingData.reward = linearPendingReward(_poolId, _account);
        stakingData.updatedTime = uint128(block.timestamp);
    }

    function getPoolIdsForAddress(address _account) external view returns(uint[] memory) {
        return linearPoolByAddress[_account];
    }
}