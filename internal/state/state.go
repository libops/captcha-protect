package state

import (
	"reflect"

	lru "github.com/patrickmn/go-cache"
)

type State struct {
	Rate     map[string]uint    `json:"rate"`
	Bots     map[string]bool    `json:"bots"`
	Verified map[string]bool    `json:"verified"`
	Memory   map[string]uintptr `json:"memory"`
}

func GetState(rateCache, botCache, verifiedCache map[string]lru.Item) State {
	state := State{
		Memory: make(map[string]uintptr, 3),
	}

	state.Rate = make(map[string]uint, len(rateCache))
	state.Memory["rate"] = reflect.TypeOf(state.Rate).Size()
	for k, v := range rateCache {
		state.Rate[k] = v.Object.(uint)
		state.Memory["rate"] += reflect.TypeOf(k).Size()
		state.Memory["rate"] += reflect.TypeOf(v).Size()
		state.Memory["rate"] += uintptr(len(k))
	}

	state.Bots = make(map[string]bool, len(botCache))
	state.Memory["bot"] = reflect.TypeOf(state.Bots).Size()
	for k, v := range botCache {
		state.Bots[k] = v.Object.(bool)
		state.Memory["bot"] += reflect.TypeOf(k).Size()
		state.Memory["bot"] += reflect.TypeOf(v).Size()
		state.Memory["bot"] += uintptr(len(k))
	}

	state.Verified = make(map[string]bool, len(verifiedCache))
	state.Memory["verified"] = reflect.TypeOf(state.Verified).Size()
	for k, v := range verifiedCache {
		state.Verified[k] = v.Object.(bool)
		state.Memory["verified"] += reflect.TypeOf(k).Size()
		state.Memory["verified"] += reflect.TypeOf(v).Size()
		state.Memory["verified"] += uintptr(len(k))
	}

	return state
}
