// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package mocks

import (
	types "github.com/mihongtech/tendermint/types"
	mock "github.com/stretchr/testify/mock"
)

// BlockStore is an autogenerated mock type for the BlockStore type
type BlockStore struct {
	mock.Mock
}

// Height provides a mock function with given fields:
func (_m *BlockStore) Height() int64 {
	ret := _m.Called()

	var r0 int64
	if rf, ok := ret.Get(0).(func() int64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int64)
	}

	return r0
}

// LoadBlockCommit provides a mock function with given fields: height
func (_m *BlockStore) LoadBlockCommit(height int64) *types.Commit {
	ret := _m.Called(height)

	var r0 *types.Commit
	if rf, ok := ret.Get(0).(func(int64) *types.Commit); ok {
		r0 = rf(height)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Commit)
		}
	}

	return r0
}

// LoadBlockMeta provides a mock function with given fields: height
func (_m *BlockStore) LoadBlockMeta(height int64) *types.BlockMeta {
	ret := _m.Called(height)

	var r0 *types.BlockMeta
	if rf, ok := ret.Get(0).(func(int64) *types.BlockMeta); ok {
		r0 = rf(height)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.BlockMeta)
		}
	}

	return r0
}
