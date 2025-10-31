import React from 'react';
import { TbThumbUp } from 'react-icons/tb';
import { FaRegCircleQuestion } from 'react-icons/fa6'

export function LikeItem({style, icons, value}) {
    return (
        <button type='button'
                className={style}>
            <span>{icons === "tb" && <TbThumbUp />}</span>
            <span>{icons === "fa6" && <FaRegCircleQuestion />}</span>
               
            <span>{value}</span>
        </button>
    );
}

