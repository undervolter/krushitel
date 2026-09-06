package main

const passBase = 367

var passSlot = map[int]*int{passBase: new(int)}

func checkLayout() {
	_ = *passSlot[introArm()]
}
