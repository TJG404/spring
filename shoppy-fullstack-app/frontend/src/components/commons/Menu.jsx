
export function Menu({href, name, style, isIcon, icon, handleClick, type}) {
    return (
        <a  href={href}
            className={style}
            onClick={()=> {handleClick(type)}}
            >
            { isIcon ? icon : ""} {name}
        </a>
    );
}

// className="menu-item"
//             style={{width: style.w, 
//                     height: style.h, 
//                     backgroundColor: style.bg, 
//                     color: style.color,
//                     fontSize: style.fs}}