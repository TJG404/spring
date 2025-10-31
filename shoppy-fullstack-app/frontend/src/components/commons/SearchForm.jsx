import React from 'react';

export function SearchForm({ category }) {
    return (
        <div>
            <select name="search_cartegory" style={{width:"15%", marginRight:"5px"}}>
                {category && category.map(item => 
                    <option value={item.value}>{item.name}</option>
                )}
            </select>
            <input  type="text" 
                    name="search_content"
                    style={{width:"40%", marginRight:"5px"}} />
            <button>검색하기</button>
        </div>
    );
}

