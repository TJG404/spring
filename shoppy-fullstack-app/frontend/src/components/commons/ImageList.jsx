import React from 'react';
import { FaPlus } from 'react-icons/fa6';

export function ImageList({imgList, className}) {
    return (
        <ul className={className}>
            {imgList && imgList.map((img, idx) =>
                <li key={idx}>
                    <img src={`/images/${img}`} />
                </li>
            )}
        </ul>
    );
}

