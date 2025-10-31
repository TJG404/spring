import React from 'react';

export function ProductAvatar({img}) {
    return (
        <div className='product-avata'>
            <img src={`/images/${img}`} alt="product-image" />
        </div>
    );
}

