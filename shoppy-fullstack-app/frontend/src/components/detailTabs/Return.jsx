import React, { useState, useEffect } from 'react';
import { getReturn } from '../../feature/product/productAPI.js';

export function Return() {
    const [returnData, setReturnData] = useState({});
    useEffect(()=> {
        const fetch = async() => {
            const jsonData = await getReturn();
            setReturnData(jsonData);
        }
        fetch();
    }, [])

    return (
        <div>
            <div style={{paddingTop:"20px"}}></div>
            <h4>{returnData && returnData.title}</h4>
            <p style={{paddingBottom:"20px"}}>{returnData && returnData.description}</p>
            <table className='review-list-content'>
                <tbody>
                    {returnData.list && returnData.list.map(item => 
                        <tr>
                            <td style={{width:"30%", textAlign:"center"}}>{item.title}</td>
                            <td>
                                <ul  style={{textAlign:"left"}}>
                                {item.infoList 
                                    && item.infoList .map(item =>
                                        <li>{item}</li>
                                    )}
                                </ul>
                            </td>
                        </tr>
                    ) }
                    <tr><td colSpan={2}></td></tr>
                </tbody>
            </table>
        </div>
    );
}

