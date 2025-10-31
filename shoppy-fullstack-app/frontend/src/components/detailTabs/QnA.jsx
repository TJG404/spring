import React, { useState, useEffect } from 'react';
import { getQna } from '../../feature/product/productAPI.js';

export function QnA({pid}) {
    const [qnaData, setQnaData] = useState([]);
    const [openQid, setOpenQid] = useState(null);
    const [isOpen, setIsOpen] = useState(true);

    useEffect(()=> {
        const fetch = async(pid) => {
            const jsonData = await getQna(pid);
            setQnaData(jsonData);
        }
        fetch(pid);
    }, []);

   const handleToggle = (qid) => {
        setOpenQid(prev => (prev === qid) ? null : qid);
   }

   const handleToggleButton = () => {
        setIsOpen(!isOpen);
   }

    return (
        <div>
            <div style={{paddingTop:"20px"}}>
                {isOpen && 
                    <button type="button" 
                            style={{backgroundColor:"green"}}
                            onClick={handleToggleButton}>
                        상품 문의</button>                    
                }
                {!isOpen && 
                    <button type="button" 
                            style={{backgroundColor:"coral"}}
                            onClick={handleToggleButton}>
                        상품 문의</button>
                }    
                {!isOpen && <span>버튼이 코랄색 입니다.</span>}            
            </div>
            <table className='review-list-content'>
                <tbody>
                    {qnaData && qnaData.map(item =>
                        <tr>
                            <td style={{width:"10%"}}>
                                {item.isComplete ? <span>답변완료</span>
                                                 : <span>답변준비중</span> }
                            </td>
                            <td style={{width:"60%"}} >
                                <span style={{cursor:"pointer"}}
                                      onClick={()=> {handleToggle(item.qid)}}>{item.title}</span>
                                {item.isLock && <span>비밀글</span>}
                                {openQid === item.qid && <span>{item.content}</span>}
                            </td>
                            <td style={{width:"15%"}}>{item.id}</td>
                            <td>{item.cdate}</td>
                        </tr>
                    )}

                    <tr>
                        <td colSpan={4}>{"<< "} 1 2 3 4 5 {" >>"}</td>
                    </tr>
                </tbody>
            </table>
        </div>
    );
}

