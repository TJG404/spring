
export function initForm(initArray) {
    
    return initArray.reduce((acc,cur) => {
            acc[cur] = "";
            return acc;
    }, {});
}