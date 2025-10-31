import React from 'react'
import { useSelector, useDispatch } from 'react-redux'
import { decrement, increment } from '../../feature/counter/counterSlice.js'

export function Counter() {
  const count = useSelector((state) => state.counter.value);
  const dispatch = useDispatch(); //해당 컴포넌트에서 이벤트(액션) 발생시 slice 요청담당

  return (
    <div>
      <div>
        <button
          aria-label="Increment value"
          onClick={() => dispatch(increment())}
        >
          Increment
        </button>
        <span>{count}</span>
        <button
          aria-label="Decrement value"
          onClick={() => dispatch(decrement())}
        >
          Decrement
        </button>
      </div>
    </div>
  )
}