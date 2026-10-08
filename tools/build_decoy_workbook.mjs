// Build-time only: run with the bundled @oai/artifact-tool runtime.
import fs from 'node:fs/promises';
import { Workbook, SpreadsheetFile } from '@oai/artifact-tool';
const out = new URL('../backend/assets/', import.meta.url);
const previews = new URL('../.artifact-previews/', import.meta.url);
await fs.mkdir(out, {recursive:true});
await fs.mkdir(previews, {recursive:true});
const wb = Workbook.create();
const s = wb.worksheets.add('Financials');
s.showGridLines = false;
s.getRange('A1:F20').format.font = {name:'Arial', size:11, color:'#172033'};
s.getRange('A1:F20').format.rowHeight = 25;
s.getRange('A1:F20').format.verticalAlignment = 'center';
s.getRange('A1:A20').format.columnWidth = 32;
s.getRange('B1:F20').format.columnWidth = 18;
s.getRange('A2').values = [['Aegis Systems | Financials']];
s.getRange('A2').format.font = {name:'Arial', size:16, bold:true, color:'#183b56'};
s.getRange('A3').values = [['FY 2025–26 · April 2025–March 2026 · INR lakh']];
s.getRange('A4').values = [['Synthetic company data for the KARMA security lab.']];
s.getRange('A6:F6').values = [['Management P&L','Q1:26','Q2:26','Q3:26','Q4:26','FY:26']];
s.getRange('A6:F6').format = {fill:'#183b56',font:{name:'Arial',size:11,color:'#ffffff',bold:true},rowHeight:30};
s.getRange('A6:F6').format.horizontalAlignment = 'center';
s.getRange('A7:E12').values = [
 ['Revenue',124,138,151,167],
 ['Cost of services',48,53,57,63],
 ['Gross profit',null,null,null,null],
 ['Payroll and administration',35,37,41,43],
 ['Operating profit',null,null,null,null],
 ['Operating margin',null,null,null,null]
];
for (const c of ['B','C','D','E']) {
 s.getRange(`${c}9`).formulas = [[`=${c}7-${c}8`]];
 s.getRange(`${c}11`).formulas = [[`=${c}9-${c}10`]];
 s.getRange(`${c}12`).formulas = [[`=${c}11/${c}7`]];
}
for (let r=7;r<=11;r++) s.getRange(`F${r}`).formulas = [[`=SUM(B${r}:E${r})`]];
s.getRange('F12').formulas = [['=F11/F7']];
s.getRange('B7:E8').format.font.color='#245bc2';
s.getRange('B10:E10').format.font.color='#245bc2';
s.getRange('B7:F11').setNumberFormat('#,##0.0;(#,##0.0);"-"');
s.getRange('B12:F12').setNumberFormat('0.0%');
s.getRange('A11:F11').format.fill='#eaf0f6';
s.getRange('A11:F11').format.font.bold=true;
s.getRange('A14').values = [['Document register']];
s.getRange('A14').format.font.bold=true;
s.getRange('A15').values = [['Open document acknowledgement page']];
s.getRange('A15').format.font.color='#245bc2';
s.getRange('A17').values = [['The acknowledgement button sends a demo event to the lab dashboard.']];
s.getRange('A18').values = [['Opening this workbook alone sends no signal. No macros or backdoor.']];
wb.recalculate();
console.log((await wb.inspect({kind:'table',range:'Financials!F7:F12',include:'values,formulas',tableMaxRows:6,tableMaxCols:1})).ndjson);
console.log((await wb.inspect({kind:'match',searchTerm:'#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A|#NUM!',options:{useRegex:true,maxResults:10}})).ndjson);
const preview = await wb.render({sheetName:'Financials',range:'A1:F20',scale:1.5,format:'png'});
await fs.writeFile(new URL('financials.png',previews),new Uint8Array(await preview.arrayBuffer()));
await (await SpreadsheetFile.exportXlsx(wb)).save(new URL('company_financials_25-26.xlsx',out).pathname.replace(/^\/([A-Za-z]:)/,'$1'));
