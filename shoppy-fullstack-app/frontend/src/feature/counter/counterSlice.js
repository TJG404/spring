import { createSlice } from '@reduxjs/toolkit'

const initialState = {
  value: 0,
}

export const counterSlice = createSlice({
  name: 'counter',
  initialState,
  reducers: {
    increment(state, action){
        state.value = state.value + 1;
    },
    decrement: (state) => {
      state.value -= 1
    },
    // incrementByAmount: (state, action) => {
    //   state.value += action.payload
    // },
  },
})

// Action creators are generated for each case reducer function
export const { increment, decrement, incrementByAmount } 
= counterSlice.actions   //API 함수 또는 컴포넌트에서 dispatch(액션함수)

export default counterSlice.reducer  //store  import